# whistledrop/utils/export_submissions.py
import sys
import os
import argparse
import shutil
import zipfile
import logging
from pathlib import Path
import datetime

# Ensure the script can find whistledrop_server modules
current_utils_dir = Path(__file__).parent.resolve()
project_root = current_utils_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from whistledrop_server.config import Config
from whistledrop_server import storage_manager # To list submissions and get paths

logger = logging.getLogger("export_submissions_util")
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler(sys.stdout)])

# File to keep track of already exported submissions (to avoid re-exporting with --all)
# This is a simple mechanism. A more robust one might use a database or richer metadata.
EXPORT_TRACKING_FILE = Path(Config.DATA_DIR) / "exported_submissions_log.txt"

def get_exported_ids() -> set[str]:
    """Reads the tracking file and returns a set of already exported submission IDs."""
    if not EXPORT_TRACKING_FILE.exists():
        return set()
    try:
        with open(EXPORT_TRACKING_FILE, 'r', encoding='utf-8') as f:
            return {line.strip() for line in f if line.strip()}
    except IOError as e:
        logger.error(f"Could not read export tracking file '{EXPORT_TRACKING_FILE}': {e}")
        return set() # Treat as if nothing was exported if file is unreadable

def mark_as_exported(submission_id: str):
    """Adds a submission ID to the tracking file."""
    try:
        with open(EXPORT_TRACKING_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{submission_id}\n")
    except IOError as e:
        logger.error(f"Could not write to export tracking file '{EXPORT_TRACKING_FILE}' for ID '{submission_id}': {e}")


def export_submission(submission_id: str, output_dir: Path, as_zip: bool) -> bool:
    """
    Exports a single submission.
    If as_zip is True, creates a ZIP archive of the submission directory.
    Otherwise, copies the entire submission directory.
    """
    submission_source_path = storage_manager.get_submission_package_path(submission_id)
    if not submission_source_path:
        logger.error(f"Submission ID '{submission_id}' not found or path is invalid. Cannot export.")
        return False

    output_dir.mkdir(parents=True, exist_ok=True) # Ensure output directory exists

    if as_zip:
        zip_filename = output_dir / f"submission_{submission_id}.zip"
        try:
            with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zf:
                for item in submission_source_path.rglob('*'): # Recursively find all files
                    if item.is_file():
                        # arcname should be relative to the submission_source_path
                        arcname = item.relative_to(submission_source_path)
                        zf.write(item, arcname=arcname)
            logger.info(f"Successfully exported submission '{submission_id}' as ZIP: {zip_filename}")
            return True
        except Exception as e_zip:
            logger.error(f"Failed to create ZIP archive for submission '{submission_id}': {e_zip}", exc_info=True)
            if zip_filename.exists(): zip_filename.unlink(missing_ok=True) # Clean up partial zip
            return False
    else: # Copy as directory
        destination_path = output_dir / submission_id
        if destination_path.exists():
            logger.warning(f"Destination directory '{destination_path}' already exists. Skipping copy for submission '{submission_id}'.")
            # Or, could add an --overwrite flag. For now, skip.
            return False # Or True if skipping is considered a non-failure for this item
        try:
            shutil.copytree(submission_source_path, destination_path)
            logger.info(f"Successfully exported submission '{submission_id}' as directory: {destination_path}")
            return True
        except Exception as e_copy:
            logger.error(f"Failed to copy directory for submission '{submission_id}': {e_copy}", exc_info=True)
            if destination_path.exists(): shutil.rmtree(destination_path, ignore_errors=True) # Clean up
            return False


def main():
    parser = argparse.ArgumentParser(
        description="WhistleDrop Server - Export Encrypted Submissions Utility. "
                    "Exports submission data for offline transfer to a journalist. "
                    "The exported data remains encrypted."
    )
    parser.add_argument(
        "--output_dir",
        type=Path,
        required=True,
        help="Directory where exported submissions (or ZIP archives) will be saved. "
             "This should be a secure location, e.g., a path on a USB drive."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--id",
        action="append", # Allows specifying --id multiple times
        help="Specific submission ID(s) to export."
    )
    group.add_argument(
        "--all_new",
        action="store_true",
        help="Export all submissions that haven't been previously exported "
             "(tracked in data/exported_submissions_log.txt)."
    )
    parser.add_argument(
        "--zip",
        action="store_true",
        help="Package each submission as an individual ZIP archive in the output directory."
    )
    parser.add_argument(
        "--force_export",
        action="store_true",
        help="Force export of submissions even if they are marked as previously exported (used with --all_new or --id)."
    )

    args = parser.parse_args()

    print("\nWhistleDrop Server - Export Encrypted Submissions Utility")
    print("---------------------------------------------------------")
    resolved_output_dir = args.output_dir.resolve()
    print(f"Exporting to: {resolved_output_dir}")
    if args.zip:
        print("Output format: Individual ZIP archives per submission.")
    else:
        print("Output format: Individual directories per submission.")
    print("---")

    if not resolved_output_dir.exists():
        try:
            resolved_output_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created output directory: {resolved_output_dir}")
        except OSError as e:
            logger.critical(f"Could not create output directory '{resolved_output_dir}': {e}. Aborting.")
            sys.exit(1)
    elif not resolved_output_dir.is_dir():
        logger.critical(f"Output path '{resolved_output_dir}' exists but is not a directory. Aborting.")
        sys.exit(1)


    submissions_to_export = []
    if args.id:
        submissions_to_export = args.id
        logger.info(f"Exporting specified submission IDs: {', '.join(submissions_to_export)}")
    elif args.all_new:
        logger.info("Attempting to export all new (not previously tracked) submissions.")
        all_server_submission_ids = storage_manager.list_submissions()
        if not args.force_export:
            already_exported_ids = get_exported_ids()
            submissions_to_export = [sid for sid in all_server_submission_ids if sid not in already_exported_ids]
            logger.info(f"Found {len(all_server_submission_ids)} total submissions on server.")
            logger.info(f"{len(already_exported_ids)} submissions marked as previously exported.")
            logger.info(f"{len(submissions_to_export)} new submissions to export.")
        else:
            submissions_to_export = all_server_submission_ids
            logger.info(f"--force_export specified. Exporting all {len(submissions_to_export)} submissions on server.")


    if not submissions_to_export:
        logger.info("No submissions selected or found to export.")
        print("--- Summary ---\nNo submissions were exported.")
        return

    success_count = 0
    failure_count = 0

    for sub_id in submissions_to_export:
        logger.info(f"Processing submission ID: {sub_id}")
        if export_submission(sub_id, resolved_output_dir, args.zip):
            success_count += 1
            if args.all_new and not args.force_export: # Only mark if exporting new and not forcing
                mark_as_exported(sub_id)
        else:
            failure_count += 1
        print("---")

    print("\n--- Export Summary ---")
    print(f"Successfully exported submissions: {success_count}")
    print(f"Failed to export submissions:    {failure_count}")
    if failure_count > 0:
        print("Check logs above for details on failures.")
    if args.all_new and not args.force_export and success_count > 0:
        print(f"Successfully exported submissions have been logged in '{EXPORT_TRACKING_FILE.resolve()}'.")
    print(f"Exported data is located in: {resolved_output_dir}")
    print("Reminder: Transfer these exported files securely (e.g., via encrypted USB) to the journalist.")
    print("---")

if __name__ == "__main__":
    # Ensure data directory exists for the tracking file, if it's the first run.
    Path(Config.DATA_DIR).mkdir(parents=True, exist_ok=True)
    main()
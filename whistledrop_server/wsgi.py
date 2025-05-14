# whistledrop/whistledrop_server/wsgi.py

# This file serves as the entry point for WSGI servers like Gunicorn.
# It imports the Flask app instance from app.py.

from whistledrop_server.app import app

# The Gunicorn command will typically be:
# gunicorn --bind <host>:<port> wsgi:app
# For example, for HTTPS with SSL certs:
# gunicorn --bind 127.0.0.1:8443 \
#          --workers 4 \
#          --certfile /path/to/cert.pem \
#          --keyfile /path/to/key.pem \
#          whistledrop_server.wsgi:app
#
# The `tor_manager.py` script handles constructing and running this Gunicorn command.

if __name__ == "__main__":
    # This block allows running the Flask app with `python wsgi.py` for development,
    # but it will use Flask's built-in development server, which is not recommended
    # for anything beyond basic testing, and it won't use Gunicorn's features or SSL by default here.
    # The `app.py`'s `if __name__ == '__main__':` block is more suitable for direct Flask dev server runs
    # as it includes SSL context loading.
    #
    # For production or full testing, use Gunicorn as specified above or via `tor_manager.py`.
    print("Running Flask app via wsgi.py using Flask's development server.")
    print("This is NOT recommended for production or full testing (no Gunicorn, no automatic SSL here).")
    print("Use `python -m whistledrop_server.app` for a dev server with SSL or `python utils/tor_manager.py` for full setup.")
    app.run(host="127.0.0.1", port=5000, debug=True) # Example: runs HTTP on port 5000
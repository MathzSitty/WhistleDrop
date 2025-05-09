from whistledrop_server.app import app

if __name__ == "__main__":
    # This allows running with `python wsgi.py` for development,
    # but it's primarily for Gunicorn.
    # Example: gunicorn --bind 127.0.0.1:5000 wsgi:app
    app.run()
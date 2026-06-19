"""Flask error handlers."""

from flask import render_template, jsonify, request


def register_error_handlers(app):

    @app.errorhandler(400)
    def bad_request(e):
        if request.path.startswith('/api/'):
            return jsonify(status='error', message='Bad request'), 400
        return render_template('errors/400.html'), 400

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith('/api/'):
            return jsonify(status='error', message='Not found'), 404
        return render_template('errors/404.html'), 404

    @app.errorhandler(413)
    def too_large(e):
        if request.path.startswith('/api/'):
            return jsonify(status='error', message='File too large (max 16MB)'), 413
        return render_template('errors/413.html'), 413

    @app.errorhandler(429)
    def rate_limited(e):
        if request.path.startswith('/api/'):
            return jsonify(status='error', message='Rate limit exceeded'), 429
        return render_template('errors/429.html'), 429

    @app.errorhandler(500)
    def server_error(e):
        if request.path.startswith('/api/'):
            return jsonify(status='error', message='Internal server error'), 500
        return render_template('errors/500.html'), 500

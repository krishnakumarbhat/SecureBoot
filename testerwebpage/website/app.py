from flask import Flask
from flask_socketio import SocketIO
from views import views

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# Initialize SocketIO
socketio = SocketIO(app)

# Register the blueprint
app.register_blueprint(views)

if __name__ == '__main__':
    socketio.run(app)

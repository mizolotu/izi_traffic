import random
import string

nmin = 1
nmax = 341307
prob_rst_client = 0.01311704249835362
prob_rst_server = 0.006325622793877136
xmin = [0.0, 0.0, 0.0]
xmax = [7200.188628196716, 65172.0, 65535.0]

HELLO_INTERVAL = 2
IDLE_TIME = 60
MAX_FAILED_CONNECTIONS = 10
PERSIST = True
HELP = """
<any shell command>
Executes the command in a shell and return its output.

upload <local_file>
Uploads <local_file> to server.

download <url> <destination>
Downloads a file through HTTP(S).

zip <archive_name> <folder>
Creates a zip archive of the folder.

screenshot
Takes a screenshot.

python <command|file>
Runs a Python command or local file.

persist
Installs the agent.

clean
Uninstalls the agent.

exit
Kills the agent.
"""

class Config:
    SECRET_KEY = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(60))
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ares.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'uploads'


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config = {
    'dev': DevelopmentConfig,
    'prod': ProductionConfig
}



from flask import Flask
from flask_restful import Resource, Api, reqparse

app = Flask(__name__)
api = Api(app)

class SendLocation(Resource):
    def post(self):
        try:
            parser = reqparse.RequestParser()
            parser.add_argument('ip', type=str, help='Device IP Adress')
            parser.add_argument('lat', type=str, help='Device Current Latitude')
            parser.add_argument('long', type=str, help='Device Current Longitude')
            args = parser.parse_args()

            _deviceIp = args['ip']
            _deviceLat = args['lat']
            _deviceLong = args['long']

            return {'IP Address': _deviceIp, 'Latitude': _deviceLat, 'Longitude': _deviceLong}

        except Exception as err:
            return {'error': str(err)}

api.add_resource(SendLocation, '/SendLocation')

if __name__ == '__main__':
    app.run(debug=True)
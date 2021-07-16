# getting information about city with API
import json
import datetime

import requests
from flask import flash, redirect, url_for
from flask_login import current_user

from settings import API_KEY as api_key


def get_info(city: str, city_id: int, user: current_user):
    
    # making request to the API url
    r = requests.get(
        f'https://api.openweathermap.org/data/2.5/weather?q={city}&units=metric&appid={api_key}'
    )

    # formatting data to python dictionary
    weather_dict = json.loads(r.text)

    # if city does not exist
    if weather_dict['cod'] == '404':
        flash("The city doesn't exist!")
        return redirect(url_for('index'))

    # retrieving and formatting the necessary data
    temp = round(weather_dict['main']['temp'])
    city_name = weather_dict['name']
    local_time = (datetime.datetime.utcnow() + datetime.timedelta(seconds=weather_dict['timezone'])).strftime("%H")
    description = weather_dict['weather'][0]['description']
    # checking for day state
    day_state = None

    if 6 <= int(local_time) <= 16:
        day_state = 'day'
    elif 17 <= int(local_time) <= 23:
        day_state = 'evening-morning'
    elif 0 <= int(local_time) <= 5:
        day_state = 'night'

    return {'time': local_time,
            'city': city_name,
            'temp': temp,
            'day_state': day_state,
            'city_id': city_id,
            'description': description,
            }

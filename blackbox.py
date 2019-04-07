import random
import numpy as np
from datetime import datetime, date, time, timedelta

user_distribution = {
    "normal": 0.99, "compromised": 0.01
}

user_velocity = {
    "normal": 30, "compromised": 5 # seconds per actions
}

user_start_action = {
    "normal": {'home': 1}, "compromised": {'home': 1} # seconds per actions
}


user_profile = {
    "normal": {
        "home": {'login successfully': 0.9, 'login failed': 0.1},
        "login successfully": { "view item": 0.98, "view profile": 0.01, "buy item":0.01},
        "login failed": {"login successfully": 0.9, "login failed": 0.08, "reset password": 0.02},
        "reset password": {"login successfully": 0.9, "login failed": 0.09, "end": 0.01},
        "logout": {"end": 1},
        "view item": {"comment": 0.05, "view item": 0.65, "buy item": 0.3},
        "buy item": {"view item": 0.2, "buy item": 0.1, "logout": 0.2, "end": 0.5},
        "view profile": { "change email": 0.05, "view payment method": 0.05, "change address": 0.05,
                          "update payment method": 0.05, "view profile": 0.05, "view item": 0.75},
        "change email": {"view profile":1},
        "change address": {"view profile":1},
        "view payment method": {"view profile":1},
        "update payment method": {"view profile":1},
        "comment": {"view item": 0.6, "buy item": 0.4},
        "end": {}
    },
    "compromised": {
        "home": {'login successfully': 0.1, 'login failed': 0.9},
        "login successfully": { "view profile": 0.99, "logout":0.005, "end": 0.005},
        "login failed": {"login successfully": 0.2, "login failed": 0.7, "end": 0.1},
        "logout": {"end": 1},
        "view item": {"view item": 0.2, "buy item": 0.8},
        "buy item": {"view item": 0.2, "buy item": 0.7, "logout": 0.05, "end": 0.05},
        "view profile": { "change email": 0.2,
                         "change address": 0.4,
                         "view profile": 0.2,
                         "buy item": 0.2},
        "change address": {"buy item": 0.9, "view profile": 0.1},
        "change email": {"buy item":0.9, "view profile": 0.1},
        "update payment method": {"buy item":0.9, "view profile": 0.1},
        "end": {}
    }
}

user_lookup = {}


def generate_userlist(nb_users):
    for role in user_profile:
        for action in user_profile[role]:
            total = 0
            for follow in user_profile[role][action]:
                total+= user_profile[role][action][follow]
            if (1 > round(total, 4) and total > 0) or round(total,4) > 1:
                print(role,action,total, 1-total)

    todays_users = []

    for i in range(nb_users):
        todays_users.append(random.choices(list(user_distribution.keys()), list(user_distribution.values()))[0])

    return todays_users

def generate_logs(todays_users, start_time):
    state = [0] * len(todays_users)
    next_actions = [random.randint(0,86400) for x in range(len(todays_users))]
    logs = []

    for i in range(len(todays_users)):
        u = todays_users[i]
        state[i] = random.choices(list(user_start_action[u].keys()),list(user_start_action[u].values()))[0]
        user_lookup[todays_users[i] + str(i)] = todays_users[i]

    while min(next_actions) < 86400:
        ind = np.argmin(next_actions)
        if state[ind] != 'end':
            population = list(user_profile[todays_users[ind]][state[ind]].keys())
            weights = list(user_profile[todays_users[ind]][state[ind]].values())
            next_action = random.choices(population, weights)[0]

            spl = next_action.split(":")
            action = spl[0]
            status = 'success'
            if len(spl) > 1:
                status = spl[1]

            entry = [str(start_time + timedelta(seconds=next_actions[ind])), todays_users[ind] + str(ind), action, status, ind, todays_users[ind]]
            state[ind] = next_action

            next_actions[ind] += random.randint(1, user_velocity[todays_users[ind]])
            state[ind] = next_action
            logs.append(entry)

        else:
            next_actions[ind] = 86400

    return logs

np.seterr(divide='ignore', invalid='ignore', over='ignore')


# Event flow oracle

## Objective of this notebook

Demonstrate how we can ingest a large quantity of log, while still being able to query about if certain events happened, without going through complex queries.

This model can't take into account the order of the events.


```python
from bitarray import bitarray
import hashlib
import numpy as np
import pandas as pd
import math
import random
from string import Template
import copy
from datetime import datetime, date, time, timedelta

%load_ext autoreload
%autoreload 2
from blackbox import generate_userlist, generate_logs

```


```python
bit_size = 22
activate_real_mode = True
activate_sampling = True
probability_of_actually_writing = 0.5
probability_of_keeping_sample = 1

random_seed = 42
```


```python

# rules
rulesets = [ 
    {"name": Template("user '$who' possible account takeover to buy physical item"),
     "conditions": [
         {"condition": Template('5x $who login failed'), "expected": True},
         {"condition": Template('$who login successfully'), "expected": True},
         {"condition": Template('$who reset password'), "expected": False},
         {"condition": Template('$who change address'), "expected": True},
         {"condition": Template('$who buy item'), "expected": True}
     ]
    },
    {"name": Template("user '$who' possible account takeover to buy virtual item"),
     "conditions": [
         {"condition": Template('3x $who login failed'), "expected": True},
         {"condition": Template('$who login successfully'), "expected": True},
         {"condition": Template('$who reset password'), "expected": False},
         {"condition": Template('$who change email'), "expected": True},
         {"condition": Template('$who buy item'), "expected": True}
     ]
    },
#     {"name": Template("user '$who' excessive buying behaviour"),
#      "conditions": [
#          {"condition": Template('$who login successfully'), "expected": True},
#          {"condition": Template('$who change email'), "expected": False},
#          {"condition": Template('20x $who buy item'), "expected": True}
#      ]
#     }
]
        
events = [
    {"user": "alice", "body": "alice login successfully"},
    {"user": "alice", "body": "alice buy item"},
    {"user": "alice", "body": "alice buy item"},
    {"user": "alice", "body": "alice buy item"},
    {"user": "alice", "body": "alice buy item"},
    {"user": "alice", "body": "alice buy item"},
    {"user": "alice", "body": "alice buy item"},
    {"user": "bob", "body": "bob login failed"},
    {"user": "bob", "body": "bob login failed"},
    {"user": "bob", "body": "bob login failed"},
    {"user": "bob", "body": "bob login failed"},
    {"user": "bob", "body": "bob login failed"},
    {"user": "bob", "body": "bob login failed"},
    {"user": "bob", "body": "bob reset password"},
    {"user": "bob", "body": "bob login successfully"},
    {"user": "bob", "body": "bob buy item"},
    {"user": "charlie", "body": "charlie login failed"},
    {"user": "charlie", "body": "charlie login failed"},
    {"user": "charlie", "body": "charlie login failed"},
    {"user": "charlie", "body": "charlie login failed"},
    {"user": "charlie", "body": "charlie login successfully"},
    {"user": "charlie", "body": "charlie change address"},
    {"user": "charlie", "body": "charlie buy item"},
    {"user": "eve", "body": "eve login failed"},
    {"user": "eve", "body": "eve login failed"},
    {"user": "eve", "body": "eve login failed"},
    {"user": "eve", "body": "eve login failed"},
    {"user": "eve", "body": "eve login failed"},
    {"user": "eve", "body": "eve login failed"},
    {"user": "eve", "body": "eve login successfully"},
    {"user": "eve", "body": "eve change address"},
    {"user": "eve", "body": "eve buy item"},
]
```


```python
bit_array_size = 2**bit_size
bit_array_accuracy_test_size = 2**bit_size

# Initialization of the array of bit
bit_array_real = bitarray(bit_array_size)
bit_array_accuracy_test = bitarray(bit_array_accuracy_test_size)

bit_array_real.setall(0)
bit_array_accuracy_test.setall(0)
print("Capacity for a theoritical maximum of ~{}M entries ({}MB)".format(math.floor(bit_array_size/2/1000000), bit_array_size/8/1024/1024))
print("Effective capacity for an 99% accuracy: ~{}M entries".format(math.floor(bit_array_size/2*0.3/1000000)))
```

    Capacity for a theoritical maximum of ~2M entries (0.5MB)
    Effective capacity for an 99% accuracy: ~0M entries



```python
def process_word(data, size):
    data_unicode = data.encode('utf-8')
    hash_md5 = hashlib.md5(data_unicode).digest()
    hash_sha1 = hashlib.sha1(data_unicode).digest()
    offset_md5 = int.from_bytes(hash_md5, "little") % size
    offset_sha1 = int.from_bytes(hash_sha1, "little") % size
    return {"data": data, "offsetMD5": offset_md5, "offsetSHA1": offset_sha1}

def record_word(array, offset):
    array[offset]=True
    
def query_oracle(array, payload):
    if array[payload['offsetMD5']] and array[payload['offsetSHA1']]:
        return True
    return False
```


```python
def execute_ruleset(array, rulesets):
    matches = []
    
    for r in rulesets:
        match = True
        for cc in r['conditions']:
            payload = process_word(cc['condition'], len(array))
            
            if query_oracle(array, payload):
                if cc['expected'] == False:
                    match = False
            else:
                if cc['expected'] != False: 
                    match = False
        if match:
            matches.append(r)
    
    return matches

def customize_rules(rulesets, user):
    blank = copy.deepcopy(rulesets)
    for r in blank:
        r['name'] = r['name'].substitute(who=user)
        r['user'] = user
        for c in r['conditions']:
            c['condition'] = c['condition'].substitute(who=user)
    return blank
```


```python
def write_to_oracle_stage2(array, body, record_chance, keep_chance, counter=1):
    result = {"word": None, "saved": False}
    
    # handling recursion and repetition of events
    if counter > 1: # limiting recursion to 100 times
        updated_body = "{}x ".format(counter) + body
    else:
        updated_body = body

    payload = process_word(updated_body, len(array))
    
    if query_oracle(array, payload) and counter < 100: # this will be true if the body was observed already
        try:
            return write_to_oracle_stage2(array, body, record_chance, keep_chance, counter+1)
        except:
            print('crash at dept {}'.format(counter))
        
    else:
        # we are at the end of the recursion, this is where real operations are done
        saved = False
        if random.random() < record_chance or counter > 1:
            saved = True
            record_word(array, payload['offsetMD5'])
            record_word(array, payload['offsetSHA1'])

        if random.random() < keep_chance:
            result['word'] = payload['data']
            result['saved'] = saved
            
        return result
```


```python
def write_to_oracle_stage1(array, event, probability_of_actually_writing=1, probability_of_keeping_sample=1):
    user = event['user']
    body = event['body']
    
    result = write_to_oracle_stage2(array, body, probability_of_actually_writing, probability_of_keeping_sample)
    result['user'] = user

    return result

def check_for_applying_rules(array, rulesets, user):
    customized_rulesets = customize_rules(rulesets, user)
    
    return execute_ruleset(array, customized_rulesets)
    
def test_for_collisions(array, event):
    user = event['user']
    body = event['word']
    
    payload = process_word(body, len(array))
    
    if array[payload['offsetMD5']] == event['saved'] and array[payload['offsetSHA1']] == event['saved']:
#         print(payload['data'], array[payload['offsetMD5']], '==', array[payload['offsetSHA1']],'==', event['saved'], "returning True")
        event['observed'] = True
        event['accurate'] = True
    else:
        if array[payload['offsetMD5']] != array[payload['offsetSHA1']]:
#             print('mismatch', payload['data'], array[payload['offsetMD5']], '!=', array[payload['offsetSHA1']], "returning True")
            event['observed'] = False
            event['accurate'] = True
        else:
#             print('else', payload['data'], 'md5', array[payload['offsetMD5']], 'sha1', array[payload['offsetSHA1']], 'expected', expected, "returning False")
            event['observed'] = False
            event['accurate'] = False
        
    return event
```


```python
%%time
def main(events):
    global bit_array_real
    global bit_array_accuracy_test
    
    global rulesets
    event_counter = 0
    sample_size = 0
    collisions = []    
    
    for e in events:
        if activate_real_mode:
            real_write_result = write_to_oracle_stage1(bit_array_real, e)
            matching_rules = check_for_applying_rules(bit_array_real, rulesets, real_write_result['user'])

            for m in matching_rules:
                print(m)

        if activate_sampling:
            sampling_write_result = write_to_oracle_stage1(bit_array_accuracy_test, e, probability_of_actually_writing, probability_of_keeping_sample)           

            if sampling_write_result['word']:
                event_counter+=1
                tested_event = test_for_collisions(bit_array_accuracy_test, sampling_write_result)
#                 print('was it correctly_classified?', correctly_classified)
            
                if not tested_event['accurate']:
                    collisions.append(tested_event)
                
    if activate_sampling:
        print("\narray capacity: {}K. used {}%".format(math.floor(bit_array_accuracy_test_size/8/1024), event_counter*2/bit_array_accuracy_test_size*100))
        print("{} misclassification over {} events: {}".format(len(collisions), event_counter, len(collisions)/event_counter))
        for c in collisions:
            print(c)

if random_seed:
    random.seed(random_seed)

bit_array_real.setall(0)
bit_array_accuracy_test.setall(0)

main(events)
```

    {'name': "user 'eve' possible account takeover to buy physical item", 'conditions': [{'condition': '5x eve login failed', 'expected': True}, {'condition': 'eve login successfully', 'expected': True}, {'condition': 'eve reset password', 'expected': False}, {'condition': 'eve change address', 'expected': True}, {'condition': 'eve buy item', 'expected': True}], 'user': 'eve'}
    
    array capacity: 512K. used 0.00152587890625%
    0 misclassification over 32 events: 0.0
    CPU times: user 9.55 ms, sys: 681 µs, total: 10.2 ms
    Wall time: 9.85 ms



```python
if random_seed:
    random.seed(random_seed)

number_of_users = 2000
all_user_lists = generate_userlist(number_of_users)
todays_user_lists = random.sample(all_user_lists, number_of_users)

print(len(todays_user_lists), 'users in the database.')
print('Type of the 15 firsts:', todays_user_lists[:15])
```

    2000 users in the database.
    Type of the 15 firsts: ['normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal']



```python
start_time = datetime(2019,1,1,0,0)
day1_logs = generate_logs(todays_user_lists, start_time)

print(len(day1_logs), 'log events generated for', len(todays_user_lists), 'users')
```

    16390 log events generated for 2000 users



```python
def transform_logs_to_pandas(logs):
    data = pd.DataFrame(np.array(logs), columns=['time', 'user', 'action', 'status', 'uidx', 'realtype'])
    
#     data['prev_path'] = data.groupby(['user'])['path'].shift(1)
#     data['prev_path'] = data['prev_path'].fillna("")
    return data
    
day1_data = transform_logs_to_pandas(day1_logs)

# Example of failed actions in the logs. uidx and realtype are "cheat" columns, and not necessary in a real case usage.
print(day1_data[day1_data['realtype'] == 'compromised'].head(10)[['time','user', 'action', 'status']])
```

                        time             user              action   status
    1    2019-01-01 00:00:22   compromised152        login failed  success
    4    2019-01-01 00:00:27   compromised152  login successfully  success
    5    2019-01-01 00:00:28   compromised152        view profile  success
    6    2019-01-01 00:00:33   compromised152            buy item  success
    7    2019-01-01 00:00:34   compromised152            buy item  success
    10   2019-01-01 00:00:38   compromised152            buy item  success
    11   2019-01-01 00:00:40   compromised152              logout  success
    12   2019-01-01 00:00:41   compromised152                 end  success
    384  2019-01-01 00:32:47  compromised1916        login failed  success
    385  2019-01-01 00:32:51  compromised1916        login failed  success



```python
%%time

if random_seed:
    random.seed(random_seed)


def full_main(df):
    global bit_array_real
    global bit_array_accuracy_test
    
    global rulesets
    event_counter = 1
    sample_size = 0
    collisions = []
    
    triggered_rules = []
    identified_users = []
    
#     print(df[df['realtype'] == 'compromised'].head(10)[['time','user', 'action', 'status']])
    
    for index, row in df.iterrows():
        e = {"user": row['user'], "body": "{} {}".format(row['user'], row['action'])}

        if activate_real_mode:
            real_write_result = write_to_oracle_stage1(bit_array_real, e)
            matching_rules = check_for_applying_rules(bit_array_real, rulesets, real_write_result['user'])

            for m in matching_rules:
                print(m)
                if m not in triggered_rules:
                    triggered_rules.append(m)
                if m['user'] not in identified_users:
                    identified_users.append(m['user'])
                
        if activate_sampling:
            sampling_write_result = write_to_oracle_stage1(bit_array_accuracy_test, e, probability_of_actually_writing, probability_of_keeping_sample)           
            
            if sampling_write_result['word']:
                event_counter+=1
                tested_event = test_for_collisions(bit_array_accuracy_test, sampling_write_result)
            
                if not tested_event['accurate']:
                    collisions.append(tested_event)


    if activate_sampling:
        print("\narray capacity: {}K. used {}%".format(math.floor(bit_array_accuracy_test_size/8/1024), event_counter*2/bit_array_accuracy_test_size*100))
        print("{} collisions over {} events: {}".format(len(collisions), event_counter, len(collisions)/event_counter))
        for c in collisions[:10]:
            print(c)
    
    return {'triggered_rules': triggered_rules, 'identified_users': identified_users}
            


bit_array_real.setall(0)
bit_array_accuracy_test.setall(0)

outcome = full_main(day1_data)
```

    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1916' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1916 login failed', 'expected': True}, {'condition': 'compromised1916 login successfully', 'expected': True}, {'condition': 'compromised1916 reset password', 'expected': False}, {'condition': 'compromised1916 change email', 'expected': True}, {'condition': 'compromised1916 buy item', 'expected': True}], 'user': 'compromised1916'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised1221' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised1221 login failed', 'expected': True}, {'condition': 'compromised1221 login successfully', 'expected': True}, {'condition': 'compromised1221 reset password', 'expected': False}, {'condition': 'compromised1221 change email', 'expected': True}, {'condition': 'compromised1221 buy item', 'expected': True}], 'user': 'compromised1221'}
    {'name': "user 'compromised250' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised250 login failed', 'expected': True}, {'condition': 'compromised250 login successfully', 'expected': True}, {'condition': 'compromised250 reset password', 'expected': False}, {'condition': 'compromised250 change email', 'expected': True}, {'condition': 'compromised250 buy item', 'expected': True}], 'user': 'compromised250'}
    {'name': "user 'compromised250' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised250 login failed', 'expected': True}, {'condition': 'compromised250 login successfully', 'expected': True}, {'condition': 'compromised250 reset password', 'expected': False}, {'condition': 'compromised250 change email', 'expected': True}, {'condition': 'compromised250 buy item', 'expected': True}], 'user': 'compromised250'}
    {'name': "user 'compromised250' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised250 login failed', 'expected': True}, {'condition': 'compromised250 login successfully', 'expected': True}, {'condition': 'compromised250 reset password', 'expected': False}, {'condition': 'compromised250 change email', 'expected': True}, {'condition': 'compromised250 buy item', 'expected': True}], 'user': 'compromised250'}
    {'name': "user 'compromised250' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised250 login failed', 'expected': True}, {'condition': 'compromised250 login successfully', 'expected': True}, {'condition': 'compromised250 reset password', 'expected': False}, {'condition': 'compromised250 change email', 'expected': True}, {'condition': 'compromised250 buy item', 'expected': True}], 'user': 'compromised250'}
    {'name': "user 'compromised250' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised250 login failed', 'expected': True}, {'condition': 'compromised250 login successfully', 'expected': True}, {'condition': 'compromised250 reset password', 'expected': False}, {'condition': 'compromised250 change email', 'expected': True}, {'condition': 'compromised250 buy item', 'expected': True}], 'user': 'compromised250'}
    {'name': "user 'compromised250' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised250 login failed', 'expected': True}, {'condition': 'compromised250 login successfully', 'expected': True}, {'condition': 'compromised250 reset password', 'expected': False}, {'condition': 'compromised250 change email', 'expected': True}, {'condition': 'compromised250 buy item', 'expected': True}], 'user': 'compromised250'}
    {'name': "user 'compromised250' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised250 login failed', 'expected': True}, {'condition': 'compromised250 login successfully', 'expected': True}, {'condition': 'compromised250 reset password', 'expected': False}, {'condition': 'compromised250 change email', 'expected': True}, {'condition': 'compromised250 buy item', 'expected': True}], 'user': 'compromised250'}
    {'name': "user 'compromised250' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised250 login failed', 'expected': True}, {'condition': 'compromised250 login successfully', 'expected': True}, {'condition': 'compromised250 reset password', 'expected': False}, {'condition': 'compromised250 change email', 'expected': True}, {'condition': 'compromised250 buy item', 'expected': True}], 'user': 'compromised250'}
    {'name': "user 'compromised250' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised250 login failed', 'expected': True}, {'condition': 'compromised250 login successfully', 'expected': True}, {'condition': 'compromised250 reset password', 'expected': False}, {'condition': 'compromised250 change email', 'expected': True}, {'condition': 'compromised250 buy item', 'expected': True}], 'user': 'compromised250'}
    {'name': "user 'compromised250' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised250 login failed', 'expected': True}, {'condition': 'compromised250 login successfully', 'expected': True}, {'condition': 'compromised250 reset password', 'expected': False}, {'condition': 'compromised250 change email', 'expected': True}, {'condition': 'compromised250 buy item', 'expected': True}], 'user': 'compromised250'}
    {'name': "user 'compromised250' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised250 login failed', 'expected': True}, {'condition': 'compromised250 login successfully', 'expected': True}, {'condition': 'compromised250 reset password', 'expected': False}, {'condition': 'compromised250 change email', 'expected': True}, {'condition': 'compromised250 buy item', 'expected': True}], 'user': 'compromised250'}
    {'name': "user 'compromised250' possible account takeover to buy virtual item", 'conditions': [{'condition': '3x compromised250 login failed', 'expected': True}, {'condition': 'compromised250 login successfully', 'expected': True}, {'condition': 'compromised250 reset password', 'expected': False}, {'condition': 'compromised250 change email', 'expected': True}, {'condition': 'compromised250 buy item', 'expected': True}], 'user': 'compromised250'}
    
    array capacity: 512K. used 0.7815837860107422%
    0 collisions over 16391 events: 0.0
    CPU times: user 6.32 s, sys: 17.8 ms, total: 6.34 s
    Wall time: 6.39 s



```python
if activate_real_mode:
    print('Users who triggered rules: {}'.format(len(outcome['identified_users'])))
    for i in outcome['identified_users']:
        print("* {}".format(i))
    print('total triggered rules: {}'.format(len(outcome['triggered_rules'])))
    print('real number of compromised accounts: {}'.format(len(day1_data[day1_data['realtype'] == 'compromised']['user'].unique())))
```

    Users who triggered rules: 3
    * compromised1916
    * compromised1221
    * compromised250
    total triggered rules: 3
    real number of compromised accounts: 24



```python
if activate_real_mode:
    print('successfully identified compromised accounts: {}'.format(day1_data[
        (day1_data['realtype'] == 'compromised') & (day1_data['user'].isin(outcome['identified_users']))
    ][['time','user', 'action', 'status']]))
```

    successfully identified compromised accounts:                     time             user              action   status
    384  2019-01-01 00:32:47  compromised1916        login failed  success
    385  2019-01-01 00:32:51  compromised1916        login failed  success
    387  2019-01-01 00:32:56  compromised1916        login failed  success
    388  2019-01-01 00:32:57  compromised1916        login failed  success
    389  2019-01-01 00:32:59  compromised1916        login failed  success
    391  2019-01-01 00:33:01  compromised1916        login failed  success
    392  2019-01-01 00:33:05  compromised1916        login failed  success
    393  2019-01-01 00:33:08  compromised1916        login failed  success
    394  2019-01-01 00:33:09  compromised1916  login successfully  success
    396  2019-01-01 00:33:10  compromised1916        view profile  success
    397  2019-01-01 00:33:15  compromised1916        change email  success
    398  2019-01-01 00:33:20  compromised1916            buy item  success
    400  2019-01-01 00:33:24  compromised1916            buy item  success
    402  2019-01-01 00:33:28  compromised1916           view item  success
    403  2019-01-01 00:33:32  compromised1916            buy item  success
    404  2019-01-01 00:33:33  compromised1916            buy item  success
    406  2019-01-01 00:33:34  compromised1916            buy item  success
    407  2019-01-01 00:33:35  compromised1916            buy item  success
    408  2019-01-01 00:33:37  compromised1916           view item  success
    410  2019-01-01 00:33:38  compromised1916            buy item  success
    412  2019-01-01 00:33:40  compromised1916            buy item  success
    413  2019-01-01 00:33:43  compromised1916           view item  success
    414  2019-01-01 00:33:48  compromised1916            buy item  success
    418  2019-01-01 00:33:53  compromised1916                 end  success



```python
if activate_real_mode:   
    print('missed compromised accounts:')
    print(day1_data[
        (day1_data['realtype'] == 'compromised') & (~day1_data['user'].isin(outcome['identified_users']))
    ][['time','user', 'action', 'status']])
```

    missed compromised accounts:
                          time             user              action   status
    1      2019-01-01 00:00:22   compromised152        login failed  success
    4      2019-01-01 00:00:27   compromised152  login successfully  success
    5      2019-01-01 00:00:28   compromised152        view profile  success
    6      2019-01-01 00:00:33   compromised152            buy item  success
    7      2019-01-01 00:00:34   compromised152            buy item  success
    10     2019-01-01 00:00:38   compromised152            buy item  success
    11     2019-01-01 00:00:40   compromised152              logout  success
    12     2019-01-01 00:00:41   compromised152                 end  success
    2003   2019-01-01 03:16:47    compromised20        login failed  success
    2005   2019-01-01 03:16:48    compromised20        login failed  success
    2007   2019-01-01 03:16:53    compromised20        login failed  success
    2008   2019-01-01 03:16:54    compromised20        login failed  success
    2009   2019-01-01 03:16:55    compromised20                 end  success
    2154   2019-01-01 03:28:03   compromised101        login failed  success
    2156   2019-01-01 03:28:05   compromised101                 end  success
    4690   2019-01-01 07:16:13  compromised1733        login failed  success
    4691   2019-01-01 07:16:14  compromised1733        login failed  success
    4693   2019-01-01 07:16:19  compromised1733        login failed  success
    4694   2019-01-01 07:16:20  compromised1733        login failed  success
    4696   2019-01-01 07:16:24  compromised1733                 end  success
    4764   2019-01-01 07:22:02   compromised766        login failed  success
    4767   2019-01-01 07:22:07   compromised766        login failed  success
    4768   2019-01-01 07:22:08   compromised766        login failed  success
    4770   2019-01-01 07:22:12   compromised766        login failed  success
    4771   2019-01-01 07:22:13   compromised766  login successfully  success
    4772   2019-01-01 07:22:14   compromised766        view profile  success
    4775   2019-01-01 07:22:19   compromised766            buy item  success
    4778   2019-01-01 07:22:23   compromised766            buy item  success
    4779   2019-01-01 07:22:25   compromised766           view item  success
    4780   2019-01-01 07:22:27   compromised766           view item  success
    ...                    ...              ...                 ...      ...
    11736  2019-01-01 17:34:42   compromised743                 end  success
    12267  2019-01-01 18:23:29   compromised372        login failed  success
    12268  2019-01-01 18:23:30   compromised372        login failed  success
    12269  2019-01-01 18:23:31   compromised372        login failed  success
    12271  2019-01-01 18:23:34   compromised372        login failed  success
    12272  2019-01-01 18:23:39   compromised372        login failed  success
    12273  2019-01-01 18:23:43   compromised372        login failed  success
    12274  2019-01-01 18:23:45   compromised372        login failed  success
    12276  2019-01-01 18:23:50   compromised372        login failed  success
    12277  2019-01-01 18:23:51   compromised372                 end  success
    12946  2019-01-01 19:22:02  compromised1295        login failed  success
    12947  2019-01-01 19:22:06  compromised1295        login failed  success
    12949  2019-01-01 19:22:08  compromised1295  login successfully  success
    12950  2019-01-01 19:22:12  compromised1295        view profile  success
    12952  2019-01-01 19:22:16  compromised1295        change email  success
    12955  2019-01-01 19:22:20  compromised1295            buy item  success
    12957  2019-01-01 19:22:21  compromised1295           view item  success
    12958  2019-01-01 19:22:24  compromised1295            buy item  success
    12960  2019-01-01 19:22:27  compromised1295            buy item  success
    12963  2019-01-01 19:22:30  compromised1295            buy item  success
    12964  2019-01-01 19:22:35  compromised1295            buy item  success
    12965  2019-01-01 19:22:40  compromised1295            buy item  success
    12968  2019-01-01 19:22:45  compromised1295            buy item  success
    12969  2019-01-01 19:22:49  compromised1295           view item  success
    12971  2019-01-01 19:22:53  compromised1295           view item  success
    12975  2019-01-01 19:22:56  compromised1295           view item  success
    12977  2019-01-01 19:22:58  compromised1295            buy item  success
    12978  2019-01-01 19:23:00  compromised1295                 end  success
    14150  2019-01-01 20:48:05  compromised1699        login failed  success
    14151  2019-01-01 20:48:06  compromised1699                 end  success
    
    [352 rows x 4 columns]



```python
if activate_real_mode:
#     print('real number of normal users that triggered rules: {}'.format(len(day1_data[day1_data['realtype'] == 'normal']['user'].unique())))
    print('Actions done by normal users who triggered rules:')
    print(day1_data[
#         (day1_data['realtype'] == 'normal') & (day1_data['user'].isin(outcome['identified_users']))
        (day1_data['realtype'] == 'normal') & (day1_data['user'] == 'normal90')
    ][['time','user', 'action', 'status']])
```

    Actions done by normal users who triggered rules:
                          time      user              action   status
    16255  2019-01-01 23:50:48  normal90  login successfully  success
    16267  2019-01-01 23:51:18  normal90           view item  success
    16268  2019-01-01 23:51:19  normal90           view item  success
    16276  2019-01-01 23:51:46  normal90            buy item  success
    16281  2019-01-01 23:52:00  normal90              logout  success
    16284  2019-01-01 23:52:24  normal90                 end  success


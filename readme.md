
# Event Flow Oracle

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
bit_size = 18
activate_real_mode = True
activate_sampling = True
probability_of_actually_writing = 0.7
probability_of_keeping_sample = 1

random_seed = 42
```


```python
bit_array_size = 2**bit_size
bit_array_accuracy_test_size = 2**bit_size

# Initialization of the array of bit
bit_array_real = bitarray(bit_array_size)
bit_array_accuracy_test = bitarray(bit_array_accuracy_test_size)

bit_array_real.setall(0)
bit_array_accuracy_test.setall(0)
print("Capacity for a theoritical maximum of ~{}K entries ({}KB)".format(math.floor(bit_array_size/2/1024), bit_array_size/8/1024))
print("Effective capacity for an 99% accuracy: ~{}M entries".format(math.floor(bit_array_size/2*0.3/1000000)))
```

    Capacity for a theoritical maximum of ~128K entries (32.0KB)
    Effective capacity for an 99% accuracy: ~0M entries



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
         {"condition": Template('2x $who login failed'), "expected": True},
         {"condition": Template('$who login successfully'), "expected": True},
         {"condition": Template('$who reset password'), "expected": False},
         {"condition": Template('$who change email'), "expected": True},
         {"condition": Template('2x $who buy item'), "expected": True}
     ]
    },
    {"name": Template("user '$who' excessive buying behaviour"),
     "conditions": [
         {"condition": Template('$who login successfully'), "expected": True},
         {"condition": Template('5x $who buy item'), "expected": True}
     ]
    }
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
    {"user": "bob", "body": "bob buy item"},
    {"user": "bob", "body": "bob buy item"},
    {"user": "bob", "body": "bob buy item"},
    {"user": "bob", "body": "bob buy item"},
    {"user": "bob", "body": "bob buy item"},
    {"user": "bob", "body": "bob buy item"},
    {"user": "bob", "body": "bob buy item"},
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
def process_word(data, size):
    data_unicode = data.encode('utf-8')
    hash_md5 = hashlib.md5(data_unicode).digest()
    hash_sha1 = hashlib.sha1(data_unicode).digest()
    offset_md5 = int.from_bytes(hash_md5, "little") % size
    offset_sha1 = int.from_bytes(hash_sha1, "little") % size
    return {"data": data, "offsetMD5": offset_md5, "offsetSHA1": offset_sha1}

def record_word(array, offsetMD5, offsetSHA1):
    array[offsetMD5]=True
    array[offsetSHA1]=True
    
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
    if counter > 1: 
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
            record_word(array, payload['offsetMD5'], payload['offsetSHA1'])

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

def check_for_applicable_rules(array, rulesets, user):
    customized_rulesets = customize_rules(rulesets, user)
    
    return execute_ruleset(array, customized_rulesets)
    
def test_for_collisions(array, event):
    # This function tries to read the exact same entry that was written by the write_to_oracle_stage1 function
    # if both bits are true and it was actually saved, then it's a true positive
    # if one of the two is true, this is a partial collision, but the code will normally interpret it as a "not observed"
    # if both bits are true, and the record was not written, then we know it's a false positive
    # if both are bits are false, and the record was not saved, then we have a true negative.
    # if both are bits are false, and the record was saved: we have a bug with the code, because this shouldn't happen
    
    user = event['user']
    body = event['word']
    
    payload = process_word(body, len(array))
    
    offset_md5 = array[payload['offsetMD5']]
    offset_sha1 = array[payload['offsetSHA1']]
    
    event['observed'] = offset_md5 and offset_sha1
    event['md5'] = offset_md5
    event['sha1'] = offset_sha1
    event['accurate'] = False
    
    if event['saved'] == True and event['observed'] == True: # Good!
        event['accurate'] = True
        event['judgment'] = { 
            'tp': 1, 'tn': 0, 
            'fp': 0, 'fn': 0
        }
    elif event['saved'] == True and event['observed'] == False: # oh oh
        event['accurate'] = False
        event['judgment'] = { 
            'tp': 0, 'tn': 1, 
            'fp': 0, 'fn': 0
        }
    elif event['saved'] == False and event['observed'] == True: # oh oh
        event['accurate'] = False
        event['judgment'] = { 
            'tp': 0, 'tn': 0, 
            'fp': 1, 'fn': 0
        }
    elif event['saved'] == False and event['observed'] == False: # Good!
        event['accurate'] = True
        event['judgment'] = { 
            'tp': 0, 'tn': 0, 
            'fp': 0, 'fn': 1
        }
    else:
        print('what am I doing here?', payload['data'], event['observed'], 'expecting', event['saved'], "returning Accurate:{}".format(event['accurate']))
        
    return event
```


```python
%%time

def alerting_function(message, event):
    print('ALERT!', message, event)


def main(events):
    global bit_array_real
    global bit_array_accuracy_test
    
    global rulesets
    event_counter = 0
    sample_size = 0
    truePositives = []
    trueNegatives = []
    falsePositives = []
    falseNegatives = []
    identified_users = []
    triggered_rules = []
    
    for e in events: # This should normaly be the input for all the logs, but I am simulating, so it's a loop
        if activate_real_mode:
            real_write_result = write_to_oracle_stage1(bit_array_real, 
                                                       e)
            
            matching_rules = check_for_applicable_rules(bit_array_real, 
                                                        rulesets, 
                                                        real_write_result['user'])

            for m in matching_rules:
                if e['user'] not in identified_users:
                    identified_users.append(e['user'])
                if m['name'] not in triggered_rules:
                    triggered_rules.append(m['name'])
                    
                alerting_function(m, e)


                
        if activate_sampling:
            sampling_write_result = write_to_oracle_stage1(bit_array_accuracy_test, 
                                                           e, 
                                                           probability_of_actually_writing, 
                                                           probability_of_keeping_sample
                                                          )           
            
            event_counter+=1
            if sampling_write_result['word']:
                sample_size+=1
                tested_event = test_for_collisions(bit_array_accuracy_test, sampling_write_result)
                
                if tested_event['judgment']['tp']:
                    truePositives.append(tested_event)
                if tested_event['judgment']['tn']:
                    trueNegatives.append(tested_event)
                if tested_event['judgment']['fp']:
                    falsePositives.append(tested_event)
                    print(event_counter, tested_event)
                if tested_event['judgment']['fn']:
                    falseNegatives.append(tested_event)
    
    print("\narray capacity: {}K. used {}%".format(math.floor(bit_array_accuracy_test_size/8/1024), event_counter*2/bit_array_accuracy_test_size*100))
    if activate_sampling:
        print('true positives (good): {}'.format(len(truePositives)))
        print('true negatives (bad): {}'.format(len(trueNegatives)))
        print('false positives (bad): {}'.format(len(falsePositives)))
        print('false negatives (good): {}'.format(len(falseNegatives)))
        print("\n{} false positives over {} events: {}".format(len(falsePositives), sample_size, len(falsePositives)/sample_size))
        for c in falsePositives:
            print('fp', c)
        for c in trueNegatives:
            print('tn', c)
    return {'identified_users': identified_users, 'triggered_rules': triggered_rules}
            
if random_seed:
    random.seed(random_seed)

bit_array_real.setall(0)
bit_array_accuracy_test.setall(0)

main(events)
```

    ALERT! {'name': "user 'alice' excessive buying behaviour", 'conditions': [{'condition': 'alice login successfully', 'expected': True}, {'condition': '5x alice buy item', 'expected': True}], 'user': 'alice'} {'user': 'alice', 'body': 'alice buy item'}
    ALERT! {'name': "user 'alice' excessive buying behaviour", 'conditions': [{'condition': 'alice login successfully', 'expected': True}, {'condition': '5x alice buy item', 'expected': True}], 'user': 'alice'} {'user': 'alice', 'body': 'alice buy item'}
    ALERT! {'name': "user 'bob' excessive buying behaviour", 'conditions': [{'condition': 'bob login successfully', 'expected': True}, {'condition': '5x bob buy item', 'expected': True}], 'user': 'bob'} {'user': 'bob', 'body': 'bob buy item'}
    ALERT! {'name': "user 'bob' excessive buying behaviour", 'conditions': [{'condition': 'bob login successfully', 'expected': True}, {'condition': '5x bob buy item', 'expected': True}], 'user': 'bob'} {'user': 'bob', 'body': 'bob buy item'}
    ALERT! {'name': "user 'bob' excessive buying behaviour", 'conditions': [{'condition': 'bob login successfully', 'expected': True}, {'condition': '5x bob buy item', 'expected': True}], 'user': 'bob'} {'user': 'bob', 'body': 'bob buy item'}
    ALERT! {'name': "user 'bob' excessive buying behaviour", 'conditions': [{'condition': 'bob login successfully', 'expected': True}, {'condition': '5x bob buy item', 'expected': True}], 'user': 'bob'} {'user': 'bob', 'body': 'bob buy item'}
    ALERT! {'name': "user 'bob' excessive buying behaviour", 'conditions': [{'condition': 'bob login successfully', 'expected': True}, {'condition': '5x bob buy item', 'expected': True}], 'user': 'bob'} {'user': 'bob', 'body': 'bob buy item'}
    ALERT! {'name': "user 'eve' possible account takeover to buy physical item", 'conditions': [{'condition': '5x eve login failed', 'expected': True}, {'condition': 'eve login successfully', 'expected': True}, {'condition': 'eve reset password', 'expected': False}, {'condition': 'eve change address', 'expected': True}, {'condition': 'eve buy item', 'expected': True}], 'user': 'eve'} {'user': 'eve', 'body': 'eve buy item'}
    
    array capacity: 32K. used 0.030517578125%
    true positives (good): 34
    true negatives (bad): 0
    false positives (bad): 0
    false negatives (good): 6
    
    0 false positives over 40 events: 0.0
    CPU times: user 19.9 ms, sys: 1.23 ms, total: 21.1 ms
    Wall time: 20.8 ms



```python
if random_seed:
    random.seed(random_seed)

number_of_users = 1000
all_user_lists = generate_userlist(number_of_users)
todays_user_lists = random.sample(all_user_lists, number_of_users)

print(len(todays_user_lists), 'users in the database.')
print('Type of the 15 firsts:', todays_user_lists[:15])
```

    1000 users in the database.
    Type of the 15 firsts: ['normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal', 'normal']



```python
start_time = datetime(2019,1,1,0,0)
day1_logs = generate_logs(todays_user_lists, start_time)

print(len(day1_logs), 'log events generated for', len(todays_user_lists), 'users')

print('* Bit Array capacity evaluated to {}%'.format(len(day1_logs)/(len(bit_array_real)/2) * 100))
```

    8282 log events generated for 1000 users
    * Bit Array capacity evaluated to 6.31866455078125%



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

                        time            user              action   status
    80   2019-01-01 00:24:58  compromised238        login failed  success
    82   2019-01-01 00:25:03  compromised238  login successfully  success
    83   2019-01-01 00:25:04  compromised238        view profile  success
    84   2019-01-01 00:25:08  compromised238            buy item  success
    85   2019-01-01 00:25:12  compromised238              logout  success
    86   2019-01-01 00:25:14  compromised238                 end  success
    720  2019-01-01 02:38:59  compromised454        login failed  success
    721  2019-01-01 02:39:00  compromised454        login failed  success
    722  2019-01-01 02:39:01  compromised454                 end  success
    727  2019-01-01 02:40:34  compromised672        login failed  success



```python
%%time

if random_seed:
    random.seed(random_seed)

def pre_main(df):
    events = []
    
    for index, row in df.iterrows():
        events.append({"user": row['user'], "body": "{} {}".format(row['user'], row['action'])})

    return main(events)

bit_array_real.setall(0)
bit_array_accuracy_test.setall(0)

outcome = pre_main(day1_data)
```

    ALERT! {'name': "user 'normal700' excessive buying behaviour", 'conditions': [{'condition': 'normal700 login successfully', 'expected': True}, {'condition': '5x normal700 buy item', 'expected': True}], 'user': 'normal700'} {'user': 'normal700', 'body': 'normal700 buy item'}
    ALERT! {'name': "user 'normal700' excessive buying behaviour", 'conditions': [{'condition': 'normal700 login successfully', 'expected': True}, {'condition': '5x normal700 buy item', 'expected': True}], 'user': 'normal700'} {'user': 'normal700', 'body': 'normal700 view item'}
    ALERT! {'name': "user 'normal700' excessive buying behaviour", 'conditions': [{'condition': 'normal700 login successfully', 'expected': True}, {'condition': '5x normal700 buy item', 'expected': True}], 'user': 'normal700'} {'user': 'normal700', 'body': 'normal700 buy item'}
    ALERT! {'name': "user 'normal700' excessive buying behaviour", 'conditions': [{'condition': 'normal700 login successfully', 'expected': True}, {'condition': '5x normal700 buy item', 'expected': True}], 'user': 'normal700'} {'user': 'normal700', 'body': 'normal700 logout'}
    ALERT! {'name': "user 'normal700' excessive buying behaviour", 'conditions': [{'condition': 'normal700 login successfully', 'expected': True}, {'condition': '5x normal700 buy item', 'expected': True}], 'user': 'normal700'} {'user': 'normal700', 'body': 'normal700 end'}
    ALERT! {'name': "user 'normal402' excessive buying behaviour", 'conditions': [{'condition': 'normal402 login successfully', 'expected': True}, {'condition': '5x normal402 buy item', 'expected': True}], 'user': 'normal402'} {'user': 'normal402', 'body': 'normal402 buy item'}
    ALERT! {'name': "user 'normal402' excessive buying behaviour", 'conditions': [{'condition': 'normal402 login successfully', 'expected': True}, {'condition': '5x normal402 buy item', 'expected': True}], 'user': 'normal402'} {'user': 'normal402', 'body': 'normal402 end'}
    ALERT! {'name': "user 'normal336' excessive buying behaviour", 'conditions': [{'condition': 'normal336 login successfully', 'expected': True}, {'condition': '5x normal336 buy item', 'expected': True}], 'user': 'normal336'} {'user': 'normal336', 'body': 'normal336 buy item'}
    ALERT! {'name': "user 'normal336' excessive buying behaviour", 'conditions': [{'condition': 'normal336 login successfully', 'expected': True}, {'condition': '5x normal336 buy item', 'expected': True}], 'user': 'normal336'} {'user': 'normal336', 'body': 'normal336 end'}
    ALERT! {'name': "user 'normal682' excessive buying behaviour", 'conditions': [{'condition': 'normal682 login successfully', 'expected': True}, {'condition': '5x normal682 buy item', 'expected': True}], 'user': 'normal682'} {'user': 'normal682', 'body': 'normal682 buy item'}
    ALERT! {'name': "user 'normal682' excessive buying behaviour", 'conditions': [{'condition': 'normal682 login successfully', 'expected': True}, {'condition': '5x normal682 buy item', 'expected': True}], 'user': 'normal682'} {'user': 'normal682', 'body': 'normal682 end'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 view item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 view item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 view item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 view item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 view item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 view item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 view item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 buy item'}
    ALERT! {'name': "user 'compromised196' excessive buying behaviour", 'conditions': [{'condition': 'compromised196 login successfully', 'expected': True}, {'condition': '5x compromised196 buy item', 'expected': True}], 'user': 'compromised196'} {'user': 'compromised196', 'body': 'compromised196 end'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' excessive buying behaviour", 'conditions': [{'condition': 'compromised516 login successfully', 'expected': True}, {'condition': '5x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' excessive buying behaviour", 'conditions': [{'condition': 'compromised516 login successfully', 'expected': True}, {'condition': '5x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' excessive buying behaviour", 'conditions': [{'condition': 'compromised516 login successfully', 'expected': True}, {'condition': '5x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' excessive buying behaviour", 'conditions': [{'condition': 'compromised516 login successfully', 'expected': True}, {'condition': '5x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 view item'}
    ALERT! {'name': "user 'compromised516' excessive buying behaviour", 'conditions': [{'condition': 'compromised516 login successfully', 'expected': True}, {'condition': '5x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 view item'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 view item'}
    ALERT! {'name': "user 'compromised516' excessive buying behaviour", 'conditions': [{'condition': 'compromised516 login successfully', 'expected': True}, {'condition': '5x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 view item'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 view item'}
    ALERT! {'name': "user 'compromised516' excessive buying behaviour", 'conditions': [{'condition': 'compromised516 login successfully', 'expected': True}, {'condition': '5x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 view item'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' excessive buying behaviour", 'conditions': [{'condition': 'compromised516 login successfully', 'expected': True}, {'condition': '5x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' excessive buying behaviour", 'conditions': [{'condition': 'compromised516 login successfully', 'expected': True}, {'condition': '5x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 buy item'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 logout'}
    ALERT! {'name': "user 'compromised516' excessive buying behaviour", 'conditions': [{'condition': 'compromised516 login successfully', 'expected': True}, {'condition': '5x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 logout'}
    ALERT! {'name': "user 'compromised516' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised516 login failed', 'expected': True}, {'condition': 'compromised516 login successfully', 'expected': True}, {'condition': 'compromised516 reset password', 'expected': False}, {'condition': 'compromised516 change email', 'expected': True}, {'condition': '2x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 end'}
    ALERT! {'name': "user 'compromised516' excessive buying behaviour", 'conditions': [{'condition': 'compromised516 login successfully', 'expected': True}, {'condition': '5x compromised516 buy item', 'expected': True}], 'user': 'compromised516'} {'user': 'compromised516', 'body': 'compromised516 end'}
    ALERT! {'name': "user 'compromised253' excessive buying behaviour", 'conditions': [{'condition': 'compromised253 login successfully', 'expected': True}, {'condition': '5x compromised253 buy item', 'expected': True}], 'user': 'compromised253'} {'user': 'compromised253', 'body': 'compromised253 buy item'}
    ALERT! {'name': "user 'compromised253' excessive buying behaviour", 'conditions': [{'condition': 'compromised253 login successfully', 'expected': True}, {'condition': '5x compromised253 buy item', 'expected': True}], 'user': 'compromised253'} {'user': 'compromised253', 'body': 'compromised253 buy item'}
    ALERT! {'name': "user 'compromised253' excessive buying behaviour", 'conditions': [{'condition': 'compromised253 login successfully', 'expected': True}, {'condition': '5x compromised253 buy item', 'expected': True}], 'user': 'compromised253'} {'user': 'compromised253', 'body': 'compromised253 buy item'}
    ALERT! {'name': "user 'compromised253' excessive buying behaviour", 'conditions': [{'condition': 'compromised253 login successfully', 'expected': True}, {'condition': '5x compromised253 buy item', 'expected': True}], 'user': 'compromised253'} {'user': 'compromised253', 'body': 'compromised253 buy item'}
    ALERT! {'name': "user 'compromised253' excessive buying behaviour", 'conditions': [{'condition': 'compromised253 login successfully', 'expected': True}, {'condition': '5x compromised253 buy item', 'expected': True}], 'user': 'compromised253'} {'user': 'compromised253', 'body': 'compromised253 end'}
    ALERT! {'name': "user 'normal440' excessive buying behaviour", 'conditions': [{'condition': 'normal440 login successfully', 'expected': True}, {'condition': '5x normal440 buy item', 'expected': True}], 'user': 'normal440'} {'user': 'normal440', 'body': 'normal440 buy item'}
    ALERT! {'name': "user 'normal440' excessive buying behaviour", 'conditions': [{'condition': 'normal440 login successfully', 'expected': True}, {'condition': '5x normal440 buy item', 'expected': True}], 'user': 'normal440'} {'user': 'normal440', 'body': 'normal440 logout'}
    ALERT! {'name': "user 'normal440' excessive buying behaviour", 'conditions': [{'condition': 'normal440 login successfully', 'expected': True}, {'condition': '5x normal440 buy item', 'expected': True}], 'user': 'normal440'} {'user': 'normal440', 'body': 'normal440 end'}
    ALERT! {'name': "user 'normal676' excessive buying behaviour", 'conditions': [{'condition': 'normal676 login successfully', 'expected': True}, {'condition': '5x normal676 buy item', 'expected': True}], 'user': 'normal676'} {'user': 'normal676', 'body': 'normal676 buy item'}
    ALERT! {'name': "user 'normal676' excessive buying behaviour", 'conditions': [{'condition': 'normal676 login successfully', 'expected': True}, {'condition': '5x normal676 buy item', 'expected': True}], 'user': 'normal676'} {'user': 'normal676', 'body': 'normal676 end'}
    ALERT! {'name': "user 'normal712' excessive buying behaviour", 'conditions': [{'condition': 'normal712 login successfully', 'expected': True}, {'condition': '5x normal712 buy item', 'expected': True}], 'user': 'normal712'} {'user': 'normal712', 'body': 'normal712 buy item'}
    ALERT! {'name': "user 'normal712' excessive buying behaviour", 'conditions': [{'condition': 'normal712 login successfully', 'expected': True}, {'condition': '5x normal712 buy item', 'expected': True}], 'user': 'normal712'} {'user': 'normal712', 'body': 'normal712 logout'}
    ALERT! {'name': "user 'normal712' excessive buying behaviour", 'conditions': [{'condition': 'normal712 login successfully', 'expected': True}, {'condition': '5x normal712 buy item', 'expected': True}], 'user': 'normal712'} {'user': 'normal712', 'body': 'normal712 end'}
    ALERT! {'name': "user 'normal807' excessive buying behaviour", 'conditions': [{'condition': 'normal807 login successfully', 'expected': True}, {'condition': '5x normal807 buy item', 'expected': True}], 'user': 'normal807'} {'user': 'normal807', 'body': 'normal807 buy item'}
    ALERT! {'name': "user 'normal807' excessive buying behaviour", 'conditions': [{'condition': 'normal807 login successfully', 'expected': True}, {'condition': '5x normal807 buy item', 'expected': True}], 'user': 'normal807'} {'user': 'normal807', 'body': 'normal807 logout'}
    ALERT! {'name': "user 'normal807' excessive buying behaviour", 'conditions': [{'condition': 'normal807 login successfully', 'expected': True}, {'condition': '5x normal807 buy item', 'expected': True}], 'user': 'normal807'} {'user': 'normal807', 'body': 'normal807 end'}
    ALERT! {'name': "user 'compromised763' excessive buying behaviour", 'conditions': [{'condition': 'compromised763 login successfully', 'expected': True}, {'condition': '5x compromised763 buy item', 'expected': True}], 'user': 'compromised763'} {'user': 'compromised763', 'body': 'compromised763 buy item'}
    ALERT! {'name': "user 'compromised763' excessive buying behaviour", 'conditions': [{'condition': 'compromised763 login successfully', 'expected': True}, {'condition': '5x compromised763 buy item', 'expected': True}], 'user': 'compromised763'} {'user': 'compromised763', 'body': 'compromised763 buy item'}
    ALERT! {'name': "user 'compromised763' excessive buying behaviour", 'conditions': [{'condition': 'compromised763 login successfully', 'expected': True}, {'condition': '5x compromised763 buy item', 'expected': True}], 'user': 'compromised763'} {'user': 'compromised763', 'body': 'compromised763 buy item'}
    ALERT! {'name': "user 'compromised763' excessive buying behaviour", 'conditions': [{'condition': 'compromised763 login successfully', 'expected': True}, {'condition': '5x compromised763 buy item', 'expected': True}], 'user': 'compromised763'} {'user': 'compromised763', 'body': 'compromised763 buy item'}
    ALERT! {'name': "user 'compromised763' excessive buying behaviour", 'conditions': [{'condition': 'compromised763 login successfully', 'expected': True}, {'condition': '5x compromised763 buy item', 'expected': True}], 'user': 'compromised763'} {'user': 'compromised763', 'body': 'compromised763 buy item'}
    ALERT! {'name': "user 'compromised763' excessive buying behaviour", 'conditions': [{'condition': 'compromised763 login successfully', 'expected': True}, {'condition': '5x compromised763 buy item', 'expected': True}], 'user': 'compromised763'} {'user': 'compromised763', 'body': 'compromised763 buy item'}
    ALERT! {'name': "user 'compromised763' excessive buying behaviour", 'conditions': [{'condition': 'compromised763 login successfully', 'expected': True}, {'condition': '5x compromised763 buy item', 'expected': True}], 'user': 'compromised763'} {'user': 'compromised763', 'body': 'compromised763 buy item'}
    ALERT! {'name': "user 'compromised763' excessive buying behaviour", 'conditions': [{'condition': 'compromised763 login successfully', 'expected': True}, {'condition': '5x compromised763 buy item', 'expected': True}], 'user': 'compromised763'} {'user': 'compromised763', 'body': 'compromised763 buy item'}
    ALERT! {'name': "user 'compromised763' excessive buying behaviour", 'conditions': [{'condition': 'compromised763 login successfully', 'expected': True}, {'condition': '5x compromised763 buy item', 'expected': True}], 'user': 'compromised763'} {'user': 'compromised763', 'body': 'compromised763 end'}
    ALERT! {'name': "user 'normal865' excessive buying behaviour", 'conditions': [{'condition': 'normal865 login successfully', 'expected': True}, {'condition': '5x normal865 buy item', 'expected': True}], 'user': 'normal865'} {'user': 'normal865', 'body': 'normal865 buy item'}
    ALERT! {'name': "user 'normal865' excessive buying behaviour", 'conditions': [{'condition': 'normal865 login successfully', 'expected': True}, {'condition': '5x normal865 buy item', 'expected': True}], 'user': 'normal865'} {'user': 'normal865', 'body': 'normal865 buy item'}
    ALERT! {'name': "user 'normal865' excessive buying behaviour", 'conditions': [{'condition': 'normal865 login successfully', 'expected': True}, {'condition': '5x normal865 buy item', 'expected': True}], 'user': 'normal865'} {'user': 'normal865', 'body': 'normal865 end'}
    ALERT! {'name': "user 'normal7' excessive buying behaviour", 'conditions': [{'condition': 'normal7 login successfully', 'expected': True}, {'condition': '5x normal7 buy item', 'expected': True}], 'user': 'normal7'} {'user': 'normal7', 'body': 'normal7 buy item'}
    ALERT! {'name': "user 'normal7' excessive buying behaviour", 'conditions': [{'condition': 'normal7 login successfully', 'expected': True}, {'condition': '5x normal7 buy item', 'expected': True}], 'user': 'normal7'} {'user': 'normal7', 'body': 'normal7 end'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 buy item'}
    ALERT! {'name': "user 'compromised300' excessive buying behaviour", 'conditions': [{'condition': 'compromised300 login successfully', 'expected': True}, {'condition': '5x compromised300 buy item', 'expected': True}], 'user': 'compromised300'} {'user': 'compromised300', 'body': 'compromised300 end'}
    ALERT! {'name': "user 'normal414' excessive buying behaviour", 'conditions': [{'condition': 'normal414 login successfully', 'expected': True}, {'condition': '5x normal414 buy item', 'expected': True}], 'user': 'normal414'} {'user': 'normal414', 'body': 'normal414 buy item'}
    ALERT! {'name': "user 'normal414' excessive buying behaviour", 'conditions': [{'condition': 'normal414 login successfully', 'expected': True}, {'condition': '5x normal414 buy item', 'expected': True}], 'user': 'normal414'} {'user': 'normal414', 'body': 'normal414 end'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' excessive buying behaviour", 'conditions': [{'condition': 'compromised434 login successfully', 'expected': True}, {'condition': '5x compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' excessive buying behaviour", 'conditions': [{'condition': 'compromised434 login successfully', 'expected': True}, {'condition': '5x compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' excessive buying behaviour", 'conditions': [{'condition': 'compromised434 login successfully', 'expected': True}, {'condition': '5x compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' excessive buying behaviour", 'conditions': [{'condition': 'compromised434 login successfully', 'expected': True}, {'condition': '5x compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 view item'}
    ALERT! {'name': "user 'compromised434' excessive buying behaviour", 'conditions': [{'condition': 'compromised434 login successfully', 'expected': True}, {'condition': '5x compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 view item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 view item'}
    ALERT! {'name': "user 'compromised434' excessive buying behaviour", 'conditions': [{'condition': 'compromised434 login successfully', 'expected': True}, {'condition': '5x compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 view item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' excessive buying behaviour", 'conditions': [{'condition': 'compromised434 login successfully', 'expected': True}, {'condition': '5x compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' excessive buying behaviour", 'conditions': [{'condition': 'compromised434 login successfully', 'expected': True}, {'condition': '5x compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' excessive buying behaviour", 'conditions': [{'condition': 'compromised434 login successfully', 'expected': True}, {'condition': '5x compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 buy item'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 logout'}
    ALERT! {'name': "user 'compromised434' excessive buying behaviour", 'conditions': [{'condition': 'compromised434 login successfully', 'expected': True}, {'condition': '5x compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 logout'}
    ALERT! {'name': "user 'compromised434' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised434 login failed', 'expected': True}, {'condition': 'compromised434 login successfully', 'expected': True}, {'condition': 'compromised434 reset password', 'expected': False}, {'condition': 'compromised434 change address', 'expected': True}, {'condition': 'compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 end'}
    ALERT! {'name': "user 'compromised434' excessive buying behaviour", 'conditions': [{'condition': 'compromised434 login successfully', 'expected': True}, {'condition': '5x compromised434 buy item', 'expected': True}], 'user': 'compromised434'} {'user': 'compromised434', 'body': 'compromised434 end'}
    ALERT! {'name': "user 'compromised354' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised354 login failed', 'expected': True}, {'condition': 'compromised354 login successfully', 'expected': True}, {'condition': 'compromised354 reset password', 'expected': False}, {'condition': 'compromised354 change address', 'expected': True}, {'condition': 'compromised354 buy item', 'expected': True}], 'user': 'compromised354'} {'user': 'compromised354', 'body': 'compromised354 buy item'}
    ALERT! {'name': "user 'compromised354' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised354 login failed', 'expected': True}, {'condition': 'compromised354 login successfully', 'expected': True}, {'condition': 'compromised354 reset password', 'expected': False}, {'condition': 'compromised354 change address', 'expected': True}, {'condition': 'compromised354 buy item', 'expected': True}], 'user': 'compromised354'} {'user': 'compromised354', 'body': 'compromised354 view item'}
    ALERT! {'name': "user 'compromised354' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised354 login failed', 'expected': True}, {'condition': 'compromised354 login successfully', 'expected': True}, {'condition': 'compromised354 reset password', 'expected': False}, {'condition': 'compromised354 change address', 'expected': True}, {'condition': 'compromised354 buy item', 'expected': True}], 'user': 'compromised354'} {'user': 'compromised354', 'body': 'compromised354 buy item'}
    ALERT! {'name': "user 'compromised354' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised354 login failed', 'expected': True}, {'condition': 'compromised354 login successfully', 'expected': True}, {'condition': 'compromised354 reset password', 'expected': False}, {'condition': 'compromised354 change address', 'expected': True}, {'condition': 'compromised354 buy item', 'expected': True}], 'user': 'compromised354'} {'user': 'compromised354', 'body': 'compromised354 buy item'}
    ALERT! {'name': "user 'compromised354' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised354 login failed', 'expected': True}, {'condition': 'compromised354 login successfully', 'expected': True}, {'condition': 'compromised354 reset password', 'expected': False}, {'condition': 'compromised354 change address', 'expected': True}, {'condition': 'compromised354 buy item', 'expected': True}], 'user': 'compromised354'} {'user': 'compromised354', 'body': 'compromised354 view item'}
    ALERT! {'name': "user 'compromised354' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised354 login failed', 'expected': True}, {'condition': 'compromised354 login successfully', 'expected': True}, {'condition': 'compromised354 reset password', 'expected': False}, {'condition': 'compromised354 change address', 'expected': True}, {'condition': 'compromised354 buy item', 'expected': True}], 'user': 'compromised354'} {'user': 'compromised354', 'body': 'compromised354 buy item'}
    ALERT! {'name': "user 'compromised354' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised354 login failed', 'expected': True}, {'condition': 'compromised354 login successfully', 'expected': True}, {'condition': 'compromised354 reset password', 'expected': False}, {'condition': 'compromised354 change address', 'expected': True}, {'condition': 'compromised354 buy item', 'expected': True}], 'user': 'compromised354'} {'user': 'compromised354', 'body': 'compromised354 logout'}
    ALERT! {'name': "user 'compromised354' possible account takeover to buy physical item", 'conditions': [{'condition': '5x compromised354 login failed', 'expected': True}, {'condition': 'compromised354 login successfully', 'expected': True}, {'condition': 'compromised354 reset password', 'expected': False}, {'condition': 'compromised354 change address', 'expected': True}, {'condition': 'compromised354 buy item', 'expected': True}], 'user': 'compromised354'} {'user': 'compromised354', 'body': 'compromised354 end'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 view item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 view item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 view item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 view item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 view item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 view item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 buy item'}
    ALERT! {'name': "user 'compromised695' excessive buying behaviour", 'conditions': [{'condition': 'compromised695 login successfully', 'expected': True}, {'condition': '5x compromised695 buy item', 'expected': True}], 'user': 'compromised695'} {'user': 'compromised695', 'body': 'compromised695 end'}
    ALERT! {'name': "user 'compromised605' excessive buying behaviour", 'conditions': [{'condition': 'compromised605 login successfully', 'expected': True}, {'condition': '5x compromised605 buy item', 'expected': True}], 'user': 'compromised605'} {'user': 'compromised605', 'body': 'compromised605 buy item'}
    ALERT! {'name': "user 'compromised605' excessive buying behaviour", 'conditions': [{'condition': 'compromised605 login successfully', 'expected': True}, {'condition': '5x compromised605 buy item', 'expected': True}], 'user': 'compromised605'} {'user': 'compromised605', 'body': 'compromised605 buy item'}
    ALERT! {'name': "user 'compromised605' excessive buying behaviour", 'conditions': [{'condition': 'compromised605 login successfully', 'expected': True}, {'condition': '5x compromised605 buy item', 'expected': True}], 'user': 'compromised605'} {'user': 'compromised605', 'body': 'compromised605 logout'}
    ALERT! {'name': "user 'compromised605' excessive buying behaviour", 'conditions': [{'condition': 'compromised605 login successfully', 'expected': True}, {'condition': '5x compromised605 buy item', 'expected': True}], 'user': 'compromised605'} {'user': 'compromised605', 'body': 'compromised605 end'}
    ALERT! {'name': "user 'compromised961' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised961 login failed', 'expected': True}, {'condition': 'compromised961 login successfully', 'expected': True}, {'condition': 'compromised961 reset password', 'expected': False}, {'condition': 'compromised961 change email', 'expected': True}, {'condition': '2x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 buy item'}
    ALERT! {'name': "user 'compromised961' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised961 login failed', 'expected': True}, {'condition': 'compromised961 login successfully', 'expected': True}, {'condition': 'compromised961 reset password', 'expected': False}, {'condition': 'compromised961 change email', 'expected': True}, {'condition': '2x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 buy item'}
    ALERT! {'name': "user 'compromised961' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised961 login failed', 'expected': True}, {'condition': 'compromised961 login successfully', 'expected': True}, {'condition': 'compromised961 reset password', 'expected': False}, {'condition': 'compromised961 change email', 'expected': True}, {'condition': '2x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 buy item'}
    ALERT! {'name': "user 'compromised961' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised961 login failed', 'expected': True}, {'condition': 'compromised961 login successfully', 'expected': True}, {'condition': 'compromised961 reset password', 'expected': False}, {'condition': 'compromised961 change email', 'expected': True}, {'condition': '2x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 buy item'}
    ALERT! {'name': "user 'compromised961' excessive buying behaviour", 'conditions': [{'condition': 'compromised961 login successfully', 'expected': True}, {'condition': '5x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 buy item'}
    ALERT! {'name': "user 'compromised961' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised961 login failed', 'expected': True}, {'condition': 'compromised961 login successfully', 'expected': True}, {'condition': 'compromised961 reset password', 'expected': False}, {'condition': 'compromised961 change email', 'expected': True}, {'condition': '2x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 view item'}
    ALERT! {'name': "user 'compromised961' excessive buying behaviour", 'conditions': [{'condition': 'compromised961 login successfully', 'expected': True}, {'condition': '5x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 view item'}
    ALERT! {'name': "user 'compromised961' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised961 login failed', 'expected': True}, {'condition': 'compromised961 login successfully', 'expected': True}, {'condition': 'compromised961 reset password', 'expected': False}, {'condition': 'compromised961 change email', 'expected': True}, {'condition': '2x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 buy item'}
    ALERT! {'name': "user 'compromised961' excessive buying behaviour", 'conditions': [{'condition': 'compromised961 login successfully', 'expected': True}, {'condition': '5x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 buy item'}
    ALERT! {'name': "user 'compromised961' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised961 login failed', 'expected': True}, {'condition': 'compromised961 login successfully', 'expected': True}, {'condition': 'compromised961 reset password', 'expected': False}, {'condition': 'compromised961 change email', 'expected': True}, {'condition': '2x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 buy item'}
    ALERT! {'name': "user 'compromised961' excessive buying behaviour", 'conditions': [{'condition': 'compromised961 login successfully', 'expected': True}, {'condition': '5x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 buy item'}
    ALERT! {'name': "user 'compromised961' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised961 login failed', 'expected': True}, {'condition': 'compromised961 login successfully', 'expected': True}, {'condition': 'compromised961 reset password', 'expected': False}, {'condition': 'compromised961 change email', 'expected': True}, {'condition': '2x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 buy item'}
    ALERT! {'name': "user 'compromised961' excessive buying behaviour", 'conditions': [{'condition': 'compromised961 login successfully', 'expected': True}, {'condition': '5x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 buy item'}
    ALERT! {'name': "user 'compromised961' possible account takeover to buy virtual item", 'conditions': [{'condition': '2x compromised961 login failed', 'expected': True}, {'condition': 'compromised961 login successfully', 'expected': True}, {'condition': 'compromised961 reset password', 'expected': False}, {'condition': 'compromised961 change email', 'expected': True}, {'condition': '2x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 end'}
    ALERT! {'name': "user 'compromised961' excessive buying behaviour", 'conditions': [{'condition': 'compromised961 login successfully', 'expected': True}, {'condition': '5x compromised961 buy item', 'expected': True}], 'user': 'compromised961'} {'user': 'compromised961', 'body': 'compromised961 end'}
    
    array capacity: 32K. used 6.31866455078125%
    true positives (good): 6807
    true negatives (bad): 0
    false positives (bad): 0
    false negatives (good): 1475
    
    0 false positives over 8282 events: 0.0
    CPU times: user 3.75 s, sys: 56.1 ms, total: 3.8 s
    Wall time: 3.79 s



```python
if activate_real_mode:
    print('Users who triggered rules: {}'.format(len(outcome['identified_users'])))
    for i in outcome['identified_users']:
        print("* {}".format(i))
    print('total triggered rules: {}'.format(len(outcome['triggered_rules'])))
    print('real number of compromised accounts: {}'.format(len(day1_data[day1_data['realtype'] == 'compromised']['user'].unique())))
```

    Users who triggered rules: 21
    * normal700
    * normal402
    * normal336
    * normal682
    * compromised196
    * compromised516
    * compromised253
    * normal440
    * normal676
    * normal712
    * normal807
    * compromised763
    * normal865
    * normal7
    * compromised300
    * normal414
    * compromised434
    * compromised354
    * compromised695
    * compromised605
    * compromised961
    total triggered rules: 24
    real number of compromised accounts: 15



```python
if activate_real_mode:
    print('successfully identified compromised accounts:')
    print(day1_data[
        (day1_data['realtype'] == 'compromised') & (day1_data['user'].isin(outcome['identified_users']))
    ][['time','user', 'action', 'status']])
```

    successfully identified compromised accounts:
                         time            user              action   status
    1339  2019-01-01 04:53:09  compromised196        login failed  success
    1341  2019-01-01 04:53:13  compromised196        login failed  success
    1342  2019-01-01 04:53:14  compromised196        login failed  success
    1343  2019-01-01 04:53:15  compromised196        login failed  success
    1346  2019-01-01 04:53:19  compromised196        login failed  success
    1347  2019-01-01 04:53:22  compromised196        login failed  success
    1348  2019-01-01 04:53:23  compromised196        login failed  success
    1350  2019-01-01 04:53:26  compromised196        login failed  success
    1351  2019-01-01 04:53:29  compromised196        login failed  success
    1353  2019-01-01 04:53:31  compromised196        login failed  success
    1354  2019-01-01 04:53:34  compromised196        login failed  success
    1356  2019-01-01 04:53:35  compromised196        login failed  success
    1358  2019-01-01 04:53:39  compromised196  login successfully  success
    1359  2019-01-01 04:53:40  compromised196        view profile  success
    1362  2019-01-01 04:53:45  compromised196        view profile  success
    1364  2019-01-01 04:53:49  compromised196            buy item  success
    1365  2019-01-01 04:53:50  compromised196           view item  success
    1366  2019-01-01 04:53:51  compromised196            buy item  success
    1367  2019-01-01 04:53:52  compromised196            buy item  success
    1368  2019-01-01 04:53:54  compromised196            buy item  success
    1370  2019-01-01 04:53:59  compromised196            buy item  success
    1372  2019-01-01 04:54:04  compromised196            buy item  success
    1373  2019-01-01 04:54:05  compromised196           view item  success
    1374  2019-01-01 04:54:07  compromised196            buy item  success
    1375  2019-01-01 04:54:08  compromised196            buy item  success
    1376  2019-01-01 04:54:13  compromised196           view item  success
    1378  2019-01-01 04:54:15  compromised196           view item  success
    1379  2019-01-01 04:54:18  compromised196            buy item  success
    1381  2019-01-01 04:54:19  compromised196            buy item  success
    1382  2019-01-01 04:54:20  compromised196            buy item  success
    ...                   ...             ...                 ...      ...
    6924  2019-01-01 20:18:38  compromised695                 end  success
    8062  2019-01-01 23:28:49  compromised605  login successfully  success
    8063  2019-01-01 23:28:50  compromised605        view profile  success
    8064  2019-01-01 23:28:55  compromised605        change email  success
    8065  2019-01-01 23:28:57  compromised605            buy item  success
    8066  2019-01-01 23:29:00  compromised605            buy item  success
    8067  2019-01-01 23:29:01  compromised605            buy item  success
    8069  2019-01-01 23:29:04  compromised605            buy item  success
    8070  2019-01-01 23:29:05  compromised605            buy item  success
    8073  2019-01-01 23:29:08  compromised605            buy item  success
    8075  2019-01-01 23:29:12  compromised605              logout  success
    8076  2019-01-01 23:29:16  compromised605                 end  success
    8078  2019-01-01 23:29:35  compromised961        login failed  success
    8079  2019-01-01 23:29:38  compromised961        login failed  success
    8081  2019-01-01 23:29:42  compromised961        login failed  success
    8082  2019-01-01 23:29:43  compromised961  login successfully  success
    8083  2019-01-01 23:29:46  compromised961        view profile  success
    8085  2019-01-01 23:29:47  compromised961        change email  success
    8086  2019-01-01 23:29:48  compromised961            buy item  success
    8087  2019-01-01 23:29:53  compromised961           view item  success
    8088  2019-01-01 23:29:55  compromised961           view item  success
    8089  2019-01-01 23:29:59  compromised961            buy item  success
    8090  2019-01-01 23:30:00  compromised961            buy item  success
    8091  2019-01-01 23:30:03  compromised961            buy item  success
    8092  2019-01-01 23:30:04  compromised961            buy item  success
    8094  2019-01-01 23:30:08  compromised961           view item  success
    8095  2019-01-01 23:30:09  compromised961            buy item  success
    8096  2019-01-01 23:30:12  compromised961            buy item  success
    8097  2019-01-01 23:30:14  compromised961            buy item  success
    8098  2019-01-01 23:30:15  compromised961                 end  success
    
    [242 rows x 4 columns]



```python
if activate_real_mode:   
    print('missed compromised accounts:')
    print(day1_data[
        (day1_data['realtype'] == 'compromised') & (~day1_data['user'].isin(outcome['identified_users']))
    ][['time','user', 'action', 'status']])
```

    missed compromised accounts:
                         time            user              action   status
    80    2019-01-01 00:24:58  compromised238        login failed  success
    82    2019-01-01 00:25:03  compromised238  login successfully  success
    83    2019-01-01 00:25:04  compromised238        view profile  success
    84    2019-01-01 00:25:08  compromised238            buy item  success
    85    2019-01-01 00:25:12  compromised238              logout  success
    86    2019-01-01 00:25:14  compromised238                 end  success
    720   2019-01-01 02:38:59  compromised454        login failed  success
    721   2019-01-01 02:39:00  compromised454        login failed  success
    722   2019-01-01 02:39:01  compromised454                 end  success
    727   2019-01-01 02:40:34  compromised672        login failed  success
    728   2019-01-01 02:40:36  compromised672        login failed  success
    729   2019-01-01 02:40:41  compromised672        login failed  success
    730   2019-01-01 02:40:42  compromised672        login failed  success
    732   2019-01-01 02:40:47  compromised672        login failed  success
    733   2019-01-01 02:40:51  compromised672        login failed  success
    734   2019-01-01 02:40:53  compromised672        login failed  success
    735   2019-01-01 02:40:58  compromised672        login failed  success
    737   2019-01-01 02:41:01  compromised672                 end  success
    884   2019-01-01 03:07:12  compromised668        login failed  success
    885   2019-01-01 03:07:13  compromised668  login successfully  success
    886   2019-01-01 03:07:15  compromised668        view profile  success
    887   2019-01-01 03:07:18  compromised668            buy item  success
    888   2019-01-01 03:07:22  compromised668                 end  success
    2794  2019-01-01 09:00:35  compromised269        login failed  success
    2795  2019-01-01 09:00:36  compromised269        login failed  success
    2796  2019-01-01 09:00:37  compromised269        login failed  success
    2798  2019-01-01 09:00:39  compromised269        login failed  success
    2799  2019-01-01 09:00:40  compromised269        login failed  success
    2802  2019-01-01 09:00:45  compromised269        login failed  success
    2803  2019-01-01 09:00:46  compromised269        login failed  success
    2804  2019-01-01 09:00:49  compromised269        login failed  success
    2806  2019-01-01 09:00:54  compromised269        login failed  success
    2807  2019-01-01 09:00:56  compromised269                 end  success



```python
if activate_real_mode:
#     print('real number of normal users that triggered rules: {}'.format(len(day1_data[day1_data['realtype'] == 'normal']['user'].unique())))
    print('Actions done by normal users who triggered rules:')
    print(day1_data[
#         (day1_data['realtype'] == 'normal') & (day1_data['user'].isin(outcome['identified_users']))
        (day1_data['realtype'] == 'normal') & (day1_data['user'] == 'normal700')
    ][['time','user', 'action', 'status']])
```

    Actions done by normal users who triggered rules:
                        time       user              action   status
    214  2019-01-01 00:57:22  normal700  login successfully  success
    215  2019-01-01 00:57:25  normal700           view item  success
    216  2019-01-01 00:57:42  normal700           view item  success
    217  2019-01-01 00:58:08  normal700           view item  success
    219  2019-01-01 00:58:28  normal700            buy item  success
    221  2019-01-01 00:58:41  normal700           view item  success
    222  2019-01-01 00:58:47  normal700           view item  success
    224  2019-01-01 00:58:52  normal700            buy item  success
    226  2019-01-01 00:59:10  normal700           view item  success
    229  2019-01-01 00:59:32  normal700           view item  success
    230  2019-01-01 00:59:33  normal700           view item  success
    234  2019-01-01 00:59:51  normal700            buy item  success
    237  2019-01-01 01:00:01  normal700            buy item  success
    241  2019-01-01 01:00:30  normal700            buy item  success
    242  2019-01-01 01:00:34  normal700           view item  success
    245  2019-01-01 01:01:00  normal700            buy item  success
    246  2019-01-01 01:01:18  normal700              logout  success
    248  2019-01-01 01:01:36  normal700                 end  success


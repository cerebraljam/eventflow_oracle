
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
bit_size = 19
activate_real_mode = True
activate_sampling = False
probability_of_actually_writing = 0.9
probability_of_keeping_sample = 0.05

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
print("Capacity for a theoritical maximum of ~{}M entries ({}MB)".format(math.floor(bit_array_size/2/1000000), bit_array_size/8/1024/1024))
print("Effective capacity for an 99% accuracy: ~{}M entries".format(math.floor(bit_array_size/2*0.3/1000000)))
```

    Capacity for a theoritical maximum of ~0M entries (0.0625MB)
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
         {"condition": Template('7x $who buy item'), "expected": True}
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
    
    offset_md5 = array[payload['offsetMD5']]
    offset_sha1 = array[payload['offsetSHA1']]
    
    event['observed'] = offset_md5 and offset_sha1
    event['accurate'] = False
    
    if event['observed'] == event['saved']:
        event['accurate'] = True
    else:
        print(payload['data'], event['observed'], 'expecting', event['saved'], "returning Accurate:{}".format(event['accurate']))
        
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
            event_counter+=1
            if sampling_write_result['word']:
                sample_size+=1
                tested_event = test_for_collisions(bit_array_accuracy_test, sampling_write_result)

                if not tested_event['accurate']:
                    print('was it correctly_classified?', tested_event)
                    collisions.append(tested_event)
                
    
    print("\narray capacity: {}K. used {}%".format(math.floor(bit_array_accuracy_test_size/8/1024), event_counter*2/bit_array_accuracy_test_size*100))
    if activate_sampling:
        print("{} misclassification over {} events: {}".format(len(collisions), sample_size, len(collisions)/sample_size))
        for c in collisions:
            print(c)

if random_seed:
    random.seed(random_seed)

bit_array_real.setall(0)
bit_array_accuracy_test.setall(0)

main(events)
```

    {'name': "user 'bob' excessive buying behaviour", 'conditions': [{'condition': 'bob login successfully', 'expected': True}, {'condition': '7x bob buy item', 'expected': True}], 'user': 'bob'}
    {'name': "user 'bob' excessive buying behaviour", 'conditions': [{'condition': 'bob login successfully', 'expected': True}, {'condition': '7x bob buy item', 'expected': True}], 'user': 'bob'}
    {'name': "user 'bob' excessive buying behaviour", 'conditions': [{'condition': 'bob login successfully', 'expected': True}, {'condition': '7x bob buy item', 'expected': True}], 'user': 'bob'}
    {'name': "user 'eve' possible account takeover to buy physical item", 'conditions': [{'condition': '5x eve login failed', 'expected': True}, {'condition': 'eve login successfully', 'expected': True}, {'condition': 'eve reset password', 'expected': False}, {'condition': 'eve change address', 'expected': True}, {'condition': 'eve buy item', 'expected': True}], 'user': 'eve'}
    
    array capacity: 64K. used 0.0%
    CPU times: user 13.5 ms, sys: 151 µs, total: 13.7 ms
    Wall time: 13.6 ms



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

print('* Bit Array capacity evaluated to {}%'.format(len(day1_logs)/(len(bit_array_real)/2) * 100))
```

    16390 log events generated for 2000 users
    * Bit Array capacity evaluated to 6.252288818359375%



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
                if m not in triggered_rules:
                    print(m['name'])
                    triggered_rules.append(m)
                if m['user'] not in identified_users:
                    identified_users.append(m['user'])
                
        if activate_sampling:
            sampling_write_result = write_to_oracle_stage1(bit_array_accuracy_test, e, probability_of_actually_writing, probability_of_keeping_sample)           
            event_counter+=1
            
            if sampling_write_result['word']:
                sample_size+=1
                tested_event = test_for_collisions(bit_array_accuracy_test, sampling_write_result)
            
                if not tested_event['accurate']:
                    print('was it correctly_classified?', tested_event)
                    collisions.append(tested_event)



    print("\narray capacity: {}K. used {}%".format(math.floor(bit_array_accuracy_test_size/8/1024), event_counter*2/bit_array_accuracy_test_size*100))
    if activate_sampling:
        print("{} collisions over {} events: {}".format(len(collisions), event_counter, len(collisions)/event_counter))
        for c in collisions[:10]:
            print(c)
    
    return {'triggered_rules': triggered_rules, 'identified_users': identified_users}
            


bit_array_real.setall(0)
bit_array_accuracy_test.setall(0)

outcome = full_main(day1_data)
```

    user 'compromised1916' possible account takeover to buy virtual item
    user 'compromised1916' excessive buying behaviour
    user 'normal869' excessive buying behaviour
    user 'compromised766' excessive buying behaviour
    user 'compromised1292' excessive buying behaviour
    user 'compromised1636' excessive buying behaviour
    user 'compromised1141' possible account takeover to buy virtual item
    user 'compromised826' excessive buying behaviour
    user 'compromised1715' excessive buying behaviour
    user 'normal306' excessive buying behaviour
    user 'compromised1323' excessive buying behaviour
    user 'compromised652' excessive buying behaviour
    user 'compromised1221' possible account takeover to buy virtual item
    user 'compromised1221' excessive buying behaviour
    user 'compromised272' excessive buying behaviour
    user 'compromised743' excessive buying behaviour
    user 'compromised250' possible account takeover to buy virtual item
    user 'compromised250' excessive buying behaviour
    user 'compromised1295' possible account takeover to buy virtual item
    user 'compromised1295' excessive buying behaviour
    
    array capacity: 64K. used 0.0003814697265625%
    CPU times: user 7.43 s, sys: 28.3 ms, total: 7.46 s
    Wall time: 7.5 s



```python
if activate_real_mode:
    print('Users who triggered rules: {}'.format(len(outcome['identified_users'])))
    for i in outcome['identified_users']:
        print("* {}".format(i))
    print('total triggered rules: {}'.format(len(outcome['triggered_rules'])))
    print('real number of compromised accounts: {}'.format(len(day1_data[day1_data['realtype'] == 'compromised']['user'].unique())))
```

    Users who triggered rules: 16
    * compromised1916
    * normal869
    * compromised766
    * compromised1292
    * compromised1636
    * compromised1141
    * compromised826
    * compromised1715
    * normal306
    * compromised1323
    * compromised652
    * compromised1221
    * compromised272
    * compromised743
    * compromised250
    * compromised1295
    total triggered rules: 20
    real number of compromised accounts: 24



```python
if activate_real_mode:
    print('successfully identified compromised accounts:')
    print(day1_data[
        (day1_data['realtype'] == 'compromised') & (day1_data['user'].isin(outcome['identified_users']))
    ][['time','user', 'action', 'status']])
```

    successfully identified compromised accounts:
                          time             user              action   status
    384    2019-01-01 00:32:47  compromised1916        login failed  success
    385    2019-01-01 00:32:51  compromised1916        login failed  success
    387    2019-01-01 00:32:56  compromised1916        login failed  success
    388    2019-01-01 00:32:57  compromised1916        login failed  success
    389    2019-01-01 00:32:59  compromised1916        login failed  success
    391    2019-01-01 00:33:01  compromised1916        login failed  success
    392    2019-01-01 00:33:05  compromised1916        login failed  success
    393    2019-01-01 00:33:08  compromised1916        login failed  success
    394    2019-01-01 00:33:09  compromised1916  login successfully  success
    396    2019-01-01 00:33:10  compromised1916        view profile  success
    397    2019-01-01 00:33:15  compromised1916        change email  success
    398    2019-01-01 00:33:20  compromised1916            buy item  success
    400    2019-01-01 00:33:24  compromised1916            buy item  success
    402    2019-01-01 00:33:28  compromised1916           view item  success
    403    2019-01-01 00:33:32  compromised1916            buy item  success
    404    2019-01-01 00:33:33  compromised1916            buy item  success
    406    2019-01-01 00:33:34  compromised1916            buy item  success
    407    2019-01-01 00:33:35  compromised1916            buy item  success
    408    2019-01-01 00:33:37  compromised1916           view item  success
    410    2019-01-01 00:33:38  compromised1916            buy item  success
    412    2019-01-01 00:33:40  compromised1916            buy item  success
    413    2019-01-01 00:33:43  compromised1916           view item  success
    414    2019-01-01 00:33:48  compromised1916            buy item  success
    418    2019-01-01 00:33:53  compromised1916                 end  success
    4764   2019-01-01 07:22:02   compromised766        login failed  success
    4767   2019-01-01 07:22:07   compromised766        login failed  success
    4768   2019-01-01 07:22:08   compromised766        login failed  success
    4770   2019-01-01 07:22:12   compromised766        login failed  success
    4771   2019-01-01 07:22:13   compromised766  login successfully  success
    4772   2019-01-01 07:22:14   compromised766        view profile  success
    ...                    ...              ...                 ...      ...
    12425  2019-01-01 18:39:28   compromised250            buy item  success
    12426  2019-01-01 18:39:33   compromised250            buy item  success
    12427  2019-01-01 18:39:34   compromised250            buy item  success
    12428  2019-01-01 18:39:37   compromised250            buy item  success
    12430  2019-01-01 18:39:42   compromised250            buy item  success
    12432  2019-01-01 18:39:44   compromised250            buy item  success
    12433  2019-01-01 18:39:48   compromised250           view item  success
    12434  2019-01-01 18:39:52   compromised250           view item  success
    12436  2019-01-01 18:39:56   compromised250           view item  success
    12437  2019-01-01 18:40:00   compromised250            buy item  success
    12440  2019-01-01 18:40:01   compromised250              logout  success
    12441  2019-01-01 18:40:05   compromised250                 end  success
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
    
    [352 rows x 4 columns]



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
    4947   2019-01-01 07:35:59  compromised1512        login failed  success
    4948   2019-01-01 07:36:04  compromised1512        login failed  success
    4950   2019-01-01 07:36:09  compromised1512        login failed  success
    4952   2019-01-01 07:36:14  compromised1512        login failed  success
    4953   2019-01-01 07:36:18  compromised1512        login failed  success
    4954   2019-01-01 07:36:23  compromised1512        login failed  success
    4955   2019-01-01 07:36:27  compromised1512        login failed  success
    4956   2019-01-01 07:36:30  compromised1512        login failed  success
    4957   2019-01-01 07:36:31  compromised1512  login successfully  success
    4958   2019-01-01 07:36:34  compromised1512        view profile  success
    ...                    ...              ...                 ...      ...
    4967   2019-01-01 07:36:44  compromised1512            buy item  success
    4968   2019-01-01 07:36:46  compromised1512           view item  success
    4969   2019-01-01 07:36:48  compromised1512            buy item  success
    4970   2019-01-01 07:36:50  compromised1512            buy item  success
    4971   2019-01-01 07:36:52  compromised1512              logout  success
    4972   2019-01-01 07:36:57  compromised1512                 end  success
    6922   2019-01-01 10:37:50   compromised184        login failed  success
    6923   2019-01-01 10:37:53   compromised184        login failed  success
    6924   2019-01-01 10:37:58   compromised184        login failed  success
    6925   2019-01-01 10:38:00   compromised184                 end  success
    10626  2019-01-01 16:07:53   compromised321  login successfully  success
    10629  2019-01-01 16:07:58   compromised321        view profile  success
    10630  2019-01-01 16:08:02   compromised321      change address  success
    10633  2019-01-01 16:08:06   compromised321            buy item  success
    10636  2019-01-01 16:08:11   compromised321            buy item  success
    10637  2019-01-01 16:08:13   compromised321           view item  success
    10639  2019-01-01 16:08:14   compromised321            buy item  success
    10643  2019-01-01 16:08:17   compromised321            buy item  success
    10644  2019-01-01 16:08:19   compromised321                 end  success
    12267  2019-01-01 18:23:29   compromised372        login failed  success
    12268  2019-01-01 18:23:30   compromised372        login failed  success
    12269  2019-01-01 18:23:31   compromised372        login failed  success
    12271  2019-01-01 18:23:34   compromised372        login failed  success
    12272  2019-01-01 18:23:39   compromised372        login failed  success
    12273  2019-01-01 18:23:43   compromised372        login failed  success
    12274  2019-01-01 18:23:45   compromised372        login failed  success
    12276  2019-01-01 18:23:50   compromised372        login failed  success
    12277  2019-01-01 18:23:51   compromised372                 end  success
    14150  2019-01-01 20:48:05  compromised1699        login failed  success
    14151  2019-01-01 20:48:06  compromised1699                 end  success
    
    [66 rows x 4 columns]



```python
if activate_real_mode:
#     print('real number of normal users that triggered rules: {}'.format(len(day1_data[day1_data['realtype'] == 'normal']['user'].unique())))
    print('Actions done by normal users who triggered rules:')
    print(day1_data[
#         (day1_data['realtype'] == 'normal') & (day1_data['user'].isin(outcome['identified_users']))
        (day1_data['realtype'] == 'normal') & (day1_data['user'] == 'normal660')
    ][['time','user', 'action', 'status']])
```

    Actions done by normal users who triggered rules:
                          time       user              action   status
    15637  2019-01-01 23:04:02  normal660  login successfully  success
    15643  2019-01-01 23:04:18  normal660           view item  success
    15650  2019-01-01 23:04:43  normal660           view item  success
    15666  2019-01-01 23:05:04  normal660            buy item  success
    15671  2019-01-01 23:05:22  normal660            buy item  success
    15675  2019-01-01 23:05:32  normal660              logout  success
    15679  2019-01-01 23:05:45  normal660                 end  success


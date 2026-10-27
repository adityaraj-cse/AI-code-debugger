import os
import sys
import json  # unused import

PASSWORD = "admin123"  # hardcoded credential - security risk


def calculate_total(items, discount=[]):  # mutable default argument
    total = 0
    temp = 0  # unused variable
    for i in items:
        total += i
    query = "SELECT * FROM orders WHERE id = " + str(total)  # SQL injection risk
    return total


def process_data(data):
    try:
        result = data['value']
        x = 1
        y = 2
        z = 3
        a = 4
        b = 5
        if result > 0:
            if result > 10:
                if result > 100:
                    if result > 1000:
                        print("very large")
        return result
    except:  # bare except
        pass


def validate_input(user_input):
    unused_var = "never used"
    if user_input == None:  # should use 'is None'
        return False
    return True


def helper_one():
    pass


def helper_two():
    pass


def very_long_function(a, b, c, d, e, f, g, h):
    step1 = a + b
    step2 = step1 + c
    step3 = step2 + d
    step4 = step3 + e
    step5 = step4 + f
    step6 = step5 + g
    step7 = step6 + h
    step8 = step7 * 2
    step9 = step8 - 1
    step10 = step9 / 2
    step11 = step10 + a
    step12 = step11 - b
    step13 = step12 + c
    step14 = step13 - d
    step15 = step14 + e
    return step15

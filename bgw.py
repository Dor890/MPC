import random
import numpy as np
import sympy
import time
import matplotlib.pyplot as plt
import tqdm

ASSIGNED_VALUES = []
MAX_COEF_VALUE = 15


def generate_prime_number(threshold):
    """
    A function that gets a threshold and returns a prime number that is smaller that the threshold.
    :param threshold: The threshold for selecting the prime number.
    :return: a prime number.
    """
    val = random.randint(0, threshold)
    while not sympy.isprime(val):
        val = random.randint(0, threshold)
    return val


class Party:
    def __init__(self, prime_number, deg):
        self.__secret = random.randint(0, prime_number - 1)
        self.__coefs = []
        for i in range(deg - 1):
            self.__coefs.append(random.randint(1, MAX_COEF_VALUE - 1))
        self.__coefs.append(self.__secret)
        self.__poly = np.poly1d(self.__coefs)
        self.assigned_value = random.randint(1, MAX_COEF_VALUE - 1)
        while self.assigned_value in ASSIGNED_VALUES:
            self.assigned_value = random.randint(1, MAX_COEF_VALUE - 1)
        ASSIGNED_VALUES.append(self.assigned_value)
        self.shares = [self.__poly(self.assigned_value)]

    def share_value(self, other_party, val):
        """
        A function that gets another party and its assigned value, and sends the value of the current party's
        polynomial on the other party's assigned value to the other party.
        :param other_party: The party that we want to share the value with.
        :param val: The other party's assigned value.
        :return: The function doesn't return anything.
        """
        other_party.add_share_from_party(self.__poly(val))

    def add_share_from_party(self, share):
        """
        A function that gets a share and appends it to the parties' array of shares.
        :param share: The share that we want to add to the array.
        :return: The function doesn't return anything.
        """
        self.shares.append(share)

    def get_assigned_value(self):
        """
        A function that returns the current party's assigned value.
        :return: the current party's assigned value.
        """
        return self.assigned_value

    def get_addition_share(self):
        """
        A function that returns the sum of the shares that the current party has.
        :return: the sum of the shares that the current party has.
        """
        return np.sum(self.shares)

    def reconstruct_share_sum(self, shares):
        """
        A function that gets a list of shares and returns the value of the addition function on 0, using the
        Lagrange Interpolation methods.
        :param shares: An array of tuples where each tuple holds a party's assigned value and the result of the addition
        function on this value.
        :return: the value of the addition function on 0.
        """
        x_vals = [shares[i][0] for i in range(len(shares))]
        y_vals = [shares[i][1] for i in range(len(shares))]
        res = 0
        for i in range(len(x_vals)):
            term = y_vals[i]
            for j in range(len(x_vals)):
                if i != j:
                    term *= (-x_vals[j]) / (x_vals[i] - x_vals[j])
            res += term
        return res

    def print_secret(self):
        """
        A function that prints the current party's secret.
        :return: The function doesn't return anything.
        """
        print(self.__secret)


if __name__ == '__main__':
    p = generate_prime_number(500)
    time_passed_by_parties = dict()
    for n in range(2, 6):
        time_passed_by_parties[n] = dict()
        t = n - 1
        start_time = time.time()
        # creating the parties
        parties = []
        for i in range(n):
            parties.append(Party(p, t))

        # input sharing phase
        for i in range(len(parties)):
            for j in range(len(parties)):
                if i != j:
                    parties[i].share_value(parties[j], parties[j].get_assigned_value())

        # Circuit emulation phase
        addition_shares = []
        for i in range(len(parties)):
            addition_shares.append((parties[i].get_assigned_value(), parties[i].get_addition_share()))

        # Output reconstruction phase - getting the sum of the secrets using Lagrange interpolation
        randomized_party = random.randint(0, n - 1)
        result = parties[randomized_party].reconstruct_share_sum(addition_shares)
        if result < 0 or result > np.power(2, 31) - 1:
            raise ValueError("An overflow has been occurred.")

        time_passed = time.time() - start_time
        time_passed_by_parties[n] = time_passed

        # Checking result
        for i in range(len(parties)):
            print(f"The secret value of party {i} is: ")
            parties[i].print_secret()
        print("The addition of the parties' secrets is: ", int(np.round(result)))

    plt.plot([key for key in time_passed_by_parties.keys()],
             [value for value in time_passed_by_parties.values()])
    plt.xlabel('Number of parties'), plt.ylabel('Time Passed (sec)')
    plt.title('BGW protocol time as a function of the number of parties')
    plt.grid(True)
    plt.tight_layout()
    # plt.show()

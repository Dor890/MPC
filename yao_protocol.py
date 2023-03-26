import random
import string
from random import randrange
import base64
from cryptography.fernet import Fernet
import hashlib
import time
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

CHARACTERS = string.ascii_letters

# Possible Gates
AND = 'AND'
XOR = 'XOR'
OR = 'OR'

CIRCUIT = 1


class Garbler:
    """
    Class represents the garbler of the circuit in the protocol.
    - Garbler knows in advance the structure of the circuit.
    - All attributes but name are secret to the other party.
    """
    def __init__(self, name, max_wire):
        self.a = None
        self.name = name
        self.input = self.rand_bits(2)  # Randomized input
        self.keys = [Fernet.generate_key() for _ in range(2*(max_wire+1))]
        self.signal_bits = [int(self.rand_bits(1)) for _ in range(max_wire+1)]
        self.lambdas = [int(self.rand_bits(1)) for _ in range(max_wire+1)]
        # self.input = '01'

    def garble_circuit(self, circuit):
        """
        Method responsible for garbling the circuit, therefore is only being
        used by the garbler.
        :param circuit: Circuit object includes all gates to be computed.
        """
        for gate in circuit.gates:
            # Set keys for each wire
            lambda_wire1 = self.lambdas[gate.input_wire_1.number]
            lambda_wire2 = self.lambdas[gate.input_wire_2.number]
            lambda_output_wire = self.lambdas[gate.output_wire.number]

            gate.input_wire_1.keys[0] = \
                self.keys[lambda_wire1 + 2*gate.input_wire_1.number]
            gate.input_wire_1.keys[1] = \
                self.keys[(1-lambda_wire1) + 2*gate.input_wire_1.number]
            gate.input_wire_2.keys[0] = \
                self.keys[lambda_wire2 + 2*gate.input_wire_2.number]
            gate.input_wire_2.keys[1] = \
                self.keys[(1-lambda_wire2) + 2*gate.input_wire_2.number]
            gate.output_wire.keys[0] = \
                self.keys[lambda_output_wire + 2*gate.output_wire.number]
            gate.output_wire.keys[1] = \
                self.keys[(1-lambda_output_wire) + 2*gate.output_wire.number]

            # Signal bits of all wires in the current gate
            wire1_signal = self.signal_bits[gate.input_wire_1.number]
            wire2_signal = self.signal_bits[gate.input_wire_2.number]
            output_signal = self.signal_bits[gate.output_wire.number]

            # Building tables depends on external values
            if gate.gate_type == XOR:
                # External values = (0, 0)
                gate.table.append(Fernet(gate.input_wire_1.keys[lambda_wire1^wire1_signal]).encrypt
                                  (Fernet(gate.input_wire_2.keys[lambda_wire2^wire2_signal]).encrypt
                                   ((gate.output_wire.keys[lambda_output_wire^(wire2_signal^wire1_signal)].decode() + str((wire1_signal^wire2_signal)^output_signal)).encode())))
                # External values = (0, 1)
                gate.table.append(Fernet(gate.input_wire_1.keys[lambda_wire1^wire1_signal]).encrypt
                                  (Fernet(gate.input_wire_2.keys[lambda_wire2^(1-wire2_signal)]).encrypt
                                   ((gate.output_wire.keys[lambda_output_wire^((wire1_signal)^(1-wire2_signal))].decode() + str(((wire1_signal^(1-wire2_signal)))^output_signal)).encode())))
                # External values = (1, 0)
                gate.table.append(Fernet(gate.input_wire_1.keys[lambda_wire1^(1-wire1_signal)]).encrypt
                                  (Fernet(gate.input_wire_2.keys[lambda_wire2^wire2_signal]).encrypt
                                   ((gate.output_wire.keys[lambda_output_wire^((1-wire1_signal)^wire2_signal)].decode() + str(((1-wire1_signal)^wire2_signal)^output_signal)).encode())))
                # External values = (1, 1)
                gate.table.append(Fernet(gate.input_wire_1.keys[lambda_wire1^(1-wire1_signal)]).encrypt
                                  (Fernet(gate.input_wire_2.keys[lambda_wire2^(1-wire2_signal)]).encrypt
                                   ((gate.output_wire.keys[lambda_output_wire^((1-wire1_signal)^(1-wire2_signal))].decode() + str(((1-wire1_signal)^(1-wire2_signal))^output_signal)).encode())))
            elif gate.gate_type == AND:
                gate.table.append(Fernet(gate.input_wire_1.keys[lambda_wire1^wire1_signal]).encrypt
                                (Fernet(gate.input_wire_2.keys[lambda_wire2^wire2_signal]).encrypt
                                ((gate.output_wire.keys[lambda_output_wire^(wire2_signal&wire1_signal)].decode() + str((wire2_signal&(wire1_signal))^output_signal)).encode())))
                gate.table.append(Fernet(gate.input_wire_1.keys[lambda_wire1^wire1_signal]).encrypt
                                (Fernet(gate.input_wire_2.keys[lambda_wire2^(1-wire2_signal)]).encrypt
                                ((gate.output_wire.keys[lambda_output_wire^(wire1_signal&(1-wire2_signal))].decode() + str((wire1_signal&(1-wire2_signal))^output_signal)).encode())))
                gate.table.append(Fernet(gate.input_wire_1.keys[lambda_wire1^(1-wire1_signal)]).encrypt
                                (Fernet(gate.input_wire_2.keys[lambda_wire2^wire2_signal]).encrypt
                                ((gate.output_wire.keys[lambda_output_wire^((1-wire1_signal)&wire2_signal)].decode() + str(((1-wire1_signal)&wire2_signal)^output_signal)).encode())))
                gate.table.append(Fernet(gate.input_wire_1.keys[lambda_wire1^(1-wire1_signal)]).encrypt
                                (Fernet(gate.input_wire_2.keys[lambda_wire2^(1-wire2_signal)]).encrypt
                                ((gate.output_wire.keys[lambda_output_wire^((1-wire1_signal)&(1-wire2_signal))].decode() + str(((1-wire1_signal)&(1-wire2_signal))^output_signal)).encode())))
            elif gate.gate_type == OR:
                gate.table.append(Fernet(gate.input_wire_1.keys[lambda_wire1^wire1_signal]).encrypt
                                  (Fernet(gate.input_wire_2.keys[lambda_wire2^wire2_signal]).encrypt
                                   ((gate.output_wire.keys[lambda_output_wire^(wire2_signal|wire1_signal)].decode() + str((wire2_signal|wire1_signal)^output_signal)).encode())))
                gate.table.append(Fernet(gate.input_wire_1.keys[lambda_wire1^wire1_signal]).encrypt
                                  (Fernet(gate.input_wire_2.keys[lambda_wire2^(1-wire2_signal)]).encrypt
                                   ((gate.output_wire.keys[lambda_output_wire^(wire1_signal|(1-wire2_signal))].decode()+str((wire1_signal|(1-wire2_signal))^output_signal)).encode())))
                gate.table.append(Fernet(gate.input_wire_1.keys[lambda_wire1^(1-wire1_signal)]).encrypt
                                  (Fernet(gate.input_wire_2.keys[lambda_wire2^wire2_signal]).encrypt
                                   ((gate.output_wire.keys[lambda_output_wire^((1-wire1_signal)|wire2_signal)].decode() + str(((1-wire1_signal)|wire2_signal)^output_signal)).encode())))
                gate.table.append(Fernet(gate.input_wire_1.keys[lambda_wire1^(1-wire1_signal)]).encrypt
                                  (Fernet(gate.input_wire_2.keys[lambda_wire2^(1-wire2_signal)]).encrypt
                                   ((gate.output_wire.keys[lambda_output_wire^((1-wire1_signal)|(1-wire2_signal))].decode()+str(((1-wire1_signal)|(1-wire2_signal))^output_signal)).encode())))
            else:
                raise Exception(gate.gate_type + ' Gate is not implemented')

        # For our specific circuit
        input_wire1_1 = circuit.gates[0].input_wire_1
        input_wire2_1 = circuit.gates[1].input_wire_1
        input_wire1_1.external_value =\
            self.signal_bits[input_wire1_1.number] ^ int(self.input[0])
        input_wire2_1.external_value =\
            self.signal_bits[input_wire2_1.number] ^ int(self.input[1])
        if self.input[0] == '0':
            del input_wire1_1.keys[1^self.lambdas[input_wire1_1.number]]
        else:
            del input_wire1_1.keys[self.lambdas[input_wire1_1.number]]
        if self.input[1] == '0':
            del input_wire2_1.keys[1^self.lambdas[input_wire2_1.number]]
        else:
            del input_wire2_1.keys[self.lambdas[input_wire2_1.number]]

        if CIRCUIT == 2:
            gate3_input = int(self.input[0]) & int(self.input[1])
            input_wire3_1 = circuit.gates[2].input_wire_1
            input_wire3_1.external_value =\
                self.signal_bits[input_wire3_1.number] ^ gate3_input
            if gate3_input == 0:
                del input_wire3_1.keys[1^self.lambdas[input_wire3_1.number]]
            else:
                del input_wire3_1.keys[self.lambdas[input_wire3_1.number]]

        # Constructing final output table
        circuit.gates[-1].output_table.append([0, self.keys[-2]])
        circuit.gates[-1].output_table.append([1, self.keys[-1]])

        # TEST - SETTING INTERMEDIATE RESULTS
        # for gate in circuit.gates[:-1]:
        #     output_wire = gate.output_wire
        #     gate.output_table.append([0, output_wire.keys[self.lambdas[output_wire.number]]])
        #     gate.output_table.append([1, output_wire.keys[1^self.lambdas[output_wire.number]]])

    def oblivious_transfer(self, evaluator, gate):
        """
        Method for executing oblivious transfer, where the sender is the
        garbler and the receiver is the evaluator, in order to receive
        the appropriate key for the evaluator.
        :param evaluator: Evaluator object that represent the receiver.
        :param gate: Gate for extracting the input wire's key.
        :return: Encrypted keys suitable for the value of the evaluator and fitted signal
         bit of input wire 2.
        """
        wire2 = gate.input_wire_2
        self.generate_fields()
        g = random.randint(1, 5)
        signal_bits = self.signal_bits[wire2.number]
        A = g ** self.a
        B = evaluator.oblivious_transfer_step_one(A, g)
        k0 = np.power(B, self.a)
        k1 = np.power((B // A), self.a)
        k0 = base64.urlsafe_b64encode(hashlib.sha256(k0.tobytes()).digest())
        k1 = base64.urlsafe_b64encode(hashlib.sha256(k1.tobytes()).digest())
        m0 = Fernet(k0).encrypt(wire2.keys[self.lambdas[wire2.number]])
        m1 = Fernet(k1).encrypt(wire2.keys[1^self.lambdas[wire2.number]])
        return m0, m1, signal_bits

    @staticmethod
    def rand_bits(n):
        """
        Helper function generates random 2^n bit strings
        """
        bits = bin(randrange(2**n))[2:].zfill(n)
        return bits

    def generate_fields(self):
        self.a = random.randint(0, 5)

class Evaluator:
    """
    Class represents the evaluator of the circuit in protocol.
     - Evaluator knows in advance the structure of the circuit.
     - Input secret to the other party.
    """
    def __init__(self, name):
        self.name = name
        self.input = self.rand_bits(2)  # Randomized input
        self.c = 0 # will be replaced as part of the oblivious transfer
        self.b = 0 # will be replaced as part of the oblivious transfer
        self.key = None # will be replaced as part of the oblivious transfer
        # self.input = '10'

    def evaluate_circuit1(self, garbled_circ, garbler):
        """
        Method used by the evaluator of the protocol in order to evaluate our
        1st circuit and eventually compute the final output.
        :param garbled_circ: Garbled circuit to be evaluated.
        :param garbler: The circuit garbler to send OTs to.
        :return: Int for the final value of the computation.
        """
        # Activate all OTs in advance
        self.c = int(self.input[0])
        gate1_m0, gate1_m1, signal_bit1 = \
            garbler.oblivious_transfer(evaluator=self, gate=garbled_circ.gates[0])
        if self.c == 0:
            gate1_wire2_key = Fernet(self.key).decrypt(gate1_m0)
        else:
            gate1_wire2_key = Fernet(self.key).decrypt(gate1_m1)
        self.c = int(self.input[1])
        gate2_m0, gate2_m1, signal_bit2 = \
            garbler.oblivious_transfer(evaluator=self, gate=garbled_circ.gates[1])
        if self.c == 0:
            gate2_wire2_key = Fernet(self.key).decrypt(gate2_m0)
        else:
            gate2_wire2_key = Fernet(self.key).decrypt(gate2_m1)
        signal_bits = [signal_bit1, signal_bit2]
        wire2_keys = [gate1_wire2_key, gate2_wire2_key]
        output_keys, output_externals = [], []

        # Evaluating gates
        for i in range(len(garbled_circ.gates) - 1):
            wire1_key = garbled_circ.gates[i].input_wire_1.keys[0]
            wire1_external = garbled_circ.gates[i].input_wire_1.external_value
            wire2_external = int(self.input[i]) ^ signal_bits[i]
            table_entry = garbled_circ.gates[i].table[2*wire1_external+wire2_external]
            inner_decrypt = Fernet(wire1_key).decrypt(table_entry)
            output = Fernet(wire2_keys[i]).decrypt(inner_decrypt)
            output_keys.append(output[:-1])
            output_externals.append(int(output.decode()[-1]))

        # TEST - EVALUATING INTERMEDIATE RESULTS
        # for gate in garbled_circ.gates:
        #     for value in gate.output_table:
        #         if output_keys[0] == value[1]:
        #             print(value[0])

        # Evaluating final gate
        table_entry = garbled_circ.gates[2].table[2*output_externals[0]+output_externals[1]]
        inner_decrypt = Fernet(output_keys[0]).decrypt(table_entry)
        output3 = Fernet(output_keys[1]).decrypt(inner_decrypt)
        final_output = output3[:-1]  # No need for external value

        # Extracting final output
        for value in garbled_circ.gates[-1].output_table:
            if final_output == value[1]:
                return value[0]

    def evaluate_circuit2(self, garbled_circ, garbler):
        """
        Method used by the evaluator of the protocol in order to evaluate our
        2nd circuit and eventually compute the final output.
        :param garbled_circ: Garbled circuit to be evaluated.
        :param garbler: The circuit garbler to send OTs to.
        :return: Int for the final value of the computation.
        """
        # Activate all OTs in advance
        input0, input1 = int(self.input[0]), int(self.input[1])
        input_gate1, input_gate2, input_gate3 = \
            1-input0, (1-input0) & (1-input1), 1-input1
        self.c = input_gate1
        gate1_m0, gate1_m1, signal_bit1 = \
            garbler.oblivious_transfer(self, garbled_circ.gates[0])
        if self.c == 0:
            gate1_wire2_key = Fernet(self.key).decrypt(gate1_m0)
        else:
            gate1_wire2_key = Fernet(self.key).decrypt(gate1_m1)
        self.c = input_gate2
        gate2_m0, gate2_m1, signal_bit2 = \
            garbler.oblivious_transfer(self, garbled_circ.gates[1])
        if self.c == 0:
            gate2_wire2_key = Fernet(self.key).decrypt(gate2_m0)
        else:
            gate2_wire2_key = Fernet(self.key).decrypt(gate2_m1)
        self.c = input_gate3
        gate3_m0, gate3_m1, signal_bit3 = \
            garbler.oblivious_transfer(self, garbled_circ.gates[2])
        if self.c == 0:
            gate3_wire2_key = Fernet(self.key).decrypt(gate3_m0)
        else:
            gate3_wire2_key = Fernet(self.key).decrypt(gate3_m1)
        signal_bits = [signal_bit1, signal_bit2, signal_bit3]
        wire2_keys = [gate1_wire2_key, gate2_wire2_key, gate3_wire2_key]
        inputs = [input_gate1, input_gate2, input_gate3]
        output_keys, output_externals = [], []

        # Evaluating first 3 AND gates
        for i in range(3):
            wire1_key = garbled_circ.gates[i].input_wire_1.keys[0]
            wire1_external = garbled_circ.gates[i].input_wire_1.external_value
            wire2_external = inputs[i] ^ signal_bits[i]
            table_entry = garbled_circ.gates[i].table[2*wire1_external+wire2_external]
            inner_decrypt = Fernet(wire1_key).decrypt(table_entry)
            output = Fernet(wire2_keys[i]).decrypt(inner_decrypt)
            output_keys.append(output[:-1])
            output_externals.append(int(output.decode()[-1]))

        # Evaluating 2 final gates
        table_entry1 = garbled_circ.gates[3].table[2*output_externals[0]+output_externals[1]]
        inner_decrypt = Fernet(output_keys[0]).decrypt(table_entry1)
        output1 = Fernet(output_keys[1]).decrypt(inner_decrypt)
        output11, output1_external = output1[:-1], int(output1.decode()[-1])

        table_entry2 = garbled_circ.gates[4].table[2*output1_external+output_externals[2]]
        inner_decrypt = Fernet(output11).decrypt(table_entry2)
        output2 = Fernet(output_keys[2]).decrypt(inner_decrypt)
        final_output = output2[:-1]  # No need for external value

        # Extracting final output
        for value in garbled_circ.gates[-1].output_table:
            if final_output == value[1]:
                return value[0]

    def oblivious_transfer_step_one(self, A, g):
        """
        A part of the oblivious transter, when the evaluator gets from the receiver the value
        of g and the value of A=g^a and returns B=g^b if the chosen bit is 0 and otherwise A * g^b.
        :param A: The value of g^a.
        :param g: A public value that both the sender and the receiver are using as part from Oblivious Transfer
        algorithm.
        :return: B=g^b if the chosen bit is 0 and otherwise A * g^b.
        """
        self.b = random.randint(0, 5)
        if self.c == 0:
            B = np.power(g, self.b)
        else:
            B = A * np.power(g, self.b)
        temp = np.power(A, self.b)
        self.key = base64.urlsafe_b64encode(hashlib.sha256(temp.tobytes()).digest())
        return B


    @staticmethod
    def rand_bits(n):
        """
        Helper function generates random 2^n bit strings
        """
        bits = bin(randrange(2**n))[2:].zfill(n)
        return bits


class Wire:
    """
    Class represents a wire of a boolean gate.
    """
    wire_number = 0

    def __init__(self):
        self.number = Wire.wire_number
        Wire.wire_number += 1
        self.keys = [0, 1]
        self.external_value = 0


class Gate:
    """
    Class represents a boolean gate in the circuit.
    """
    def __init__(self, gate_type, input_wire_1=None, input_wire_2=None):
        self.gate_type = gate_type
        self.input_wire_1, self.input_wire_2 = input_wire_1, input_wire_2
        if not input_wire_1:
            self.input_wire_1 = Wire()
        if not input_wire_2:
            self.input_wire_2 = Wire()
        self.output_wire = Wire()
        self.table = []
        self.output_table = []  # Only used for final output gate


class Circuit:
    """
    Class represents a circuit defined as list of gates.
    """
    def __init__(self):
        self.gates = []
        self.max_wire = 0

    def build_circuit(self, gates):
        """
        Method responsible for building the circuit.
        :param gates: Gates objects to be added to the circuit.
        """
        for gate in gates:
            self.gates.append(gate)
        self.max_wire = gates[-1].output_wire.number


def run_protocol():
    """
    Runs the protocol on the circuit according to STATE.
    """
    # Build our circuit
    circuit = Circuit()
    if CIRCUIT == 1:
        gate1, gate2 = Gate(AND), Gate(XOR)
        gate3 = Gate(AND, input_wire_1=gate1.output_wire,
                     input_wire_2=gate2.output_wire)
        gates = [gate1, gate2, gate3]
        circuit.build_circuit(gates)
    elif CIRCUIT == 2:
        gate1 = Gate(AND)
        gate2 = Gate(AND)
        gate3 = Gate(AND)
        gate4 = Gate(OR, input_wire_1=gate1.output_wire, input_wire_2=gate2.output_wire)
        gate5 = Gate(OR, input_wire_1=gate4.output_wire, input_wire_2=gate3.output_wire)
        gates = [gate1, gate2, gate3, gate4, gate5]
        circuit.build_circuit(gates)
    else:
        raise Exception('STATE does not exists.')

    # Creating parties participates in the protocol
    alice = Garbler('Alice', circuit.max_wire)
    bob = Evaluator('Bob')

    # Alice garbles the circuit gate by gate and creates all tables
    alice.garble_circuit(circuit)

    # Bob evaluates the circuit gate by gate
    if CIRCUIT == 1:
        output = bob.evaluate_circuit1(circuit, alice)
    elif CIRCUIT == 2:
        output = bob.evaluate_circuit2(circuit, alice)

    # Print the inputs and final output for verifying results
    # print("Alice's input:", alice.input)
    # print("Bob's input:", bob.input)
    # print("Output:", output)
    # if CIRCUIT == 1:
    #     print("Expected output:", (int(alice.input[0])&int(bob.input[0])) &
    #                             (int(alice.input[1])^int(bob.input[1])))
    # if CIRCUIT == 2:
    #     print("Expected output:", int(alice.input > bob.input))


def main():
    # Time to run the protocol on circuit STATE for ITERATIONS times.
    mpl.use('TkAgg')
    ITERATIONS = 1000
    time_passed, iteration = list(), list()
    start_time = time.time()
    for i in range(1, ITERATIONS):
        run_protocol()
        if i % 10 == 0:
            iteration.append(i)
            time_passed.append(time.time()-start_time)
    plt.plot(iteration, time_passed)
    plt.xlabel('Iteration'), plt.ylabel('Time Passed (sec)')
    plt.title('Time to preform {} iterations in circuit {}'.
              format(ITERATIONS, CIRCUIT))
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('Circuit{}'.format(CIRCUIT))
    plt.show()


if __name__ == '__main__':
    run_protocol()
    main()

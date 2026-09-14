# cipher Overview:
"""
    This cipher generates instruction based keys composed of pairs of action values and numeric values.
    Keys determine operations executed on both the plain text as well as a substitution alphabet depending on the action values read.

    This is a symmetric encryption algorithm, meaning that only one key is utilized to both encrypt and decrypt text.
    Inspiration for this encryption algorithm is taken from both classic ciphers as well as block encryption algorithms.

    Because this encryption algorithm is block based, it utilizes padding during the encryption process.
    Although I would've liked to implement dynamic block lengths, this algorithm uses a predetermined fixed block length for simplicity.

    The algorithm relies on two main components:
        1. Permutations and substitutions of the actual plain text.
        2. Permutations of the substitution alphabet.

    This algorithm encrypts one block at a time while retaining a global subtitution alphabet that is continously mutated across all blocks.
    This means that each block begins with a unique substitution alphabet which it will modify during its encryption process.
    In order to decrypt the cipher text, the substitution alphabet must first be reconstructed before decryption may begin.
"""

import sys 
import random
from dataclasses import dataclass

# Utility class used to track swaps during reconstruction
@dataclass
class Swap:
    i: int
    j: int

#Default Alphabet (used for mappings)
#Currently the alphabet length must be divisible by 8, otherwise decryption will occasionally fail due to the way blockify splits the lists.
ALPHABET ="abcdefghijklmnopqrstuvwxyz0123456789 -_."
# Substitution map is preshuffled to ensure that in the case that no action value modifies the alphabet it is still randomized
SUBSTITUTION_MAP = ['k', '2', 'q', 'd', 'y', 'g', 'u', '8', 'b', 'r', 'z', 'w', '5', 't', 'o', 'm', '3', 'p', 's', 'i', '0', 'l', 'x', '6', 'c', 'n', 'e', '9', 'a', 'j', 'h', '4', 'f', '1', 'v', '7', " ", '-', '_', '.']

# Block length, predefined for simplicity
BLOCK_LENGTH = 8

# Action values determine what type of operations are carried out by the encryption algorithm
# When keys are generated they always begin with an action value and are followed by
# a numeric value (#n) which determines how many cycles the action is carried out for.
""" 
    Substitution Alteration Values (Substitutions applied to plaintext immediately after alterations):
        A: Rotate substitution alphabet letters #n times to the right to be used as new substitution alphabet.
        B: Swap substitution alphabet block at postition 0 to #n%numBlocks.
        C: Fibonacci swap substitution alphabet letters #n times.
        D: Fibonacci Swap substitiution alphabet letters between block at position n with block at position n+1, n times.
    Action Values
        E: Rotate plaintext letters #n times to the right.
        F: Swap plaintext block at postition 0 to #n%numBlocks.
        G: Fibonacci swap plaintext letters #n times.
    H: Fibonacci Swap plaintext letters between block at position x with x+1 #n times. 
"""
 
ACTION_VALUES = ['A','B','C','D','E','F','G','H']
SUBSTITUTION_VALUES = ['A','B','C','D']

#Key Generation Rules:
"""
    Key generation follows a very simple ruleset: 
        1. Keys must begin with an action value picked from a predefined action value list.
        2. Action values must be followed by a numeric value.
        3. Numeric values must be followed be an action value.
        4. Numeric values range 1-9 cycles.
        5. Keys must be 64 characters in length.
"""
#Key Generation Algorithm Overview:
"""
    Since the substitution alphabet is an important part of this encryption method some things must happen for it to be effective:
        - The substitutaion alphabet must be used at least once before the end of the key.

    To guarantee this, the algorithm will ensure that one quarter of the key contains substitution alterations.

    Outline:
        - Generate 8 alterations (8 alterations = 16 characters counting the numerical values).
            -Randomly select numerical values
        - Generate 24 actions (24 actions = 48 characters as each action requires a numerical value).
            -Randomly select numerical values
        - Shuffle all actions together

    Additional information:
        - The key will be reused for each block, however since we are not resetting the alphabet for each block we obtain a unique substitution alphabet.
"""
def generate_key() -> str:
    key = []
    substitutions = []
    actions = []

    # Select random substitutions
    for i in range(8):
        substitutions.append(random.choice(SUBSTITUTION_VALUES))
    # Select random actions
    for i in range(24):
        actions.append(random.choice(ACTION_VALUES))

    # Join actions and substitutions then shuffle
    selected = actions + substitutions
    random.shuffle(selected)

    # Add numerical values
    for action in selected:
        number = random.randint(1,9)
        key.append(action + str(number))
    
    # Convert to string
    key = "".join(key)

    return key 

"""
    Encryption function, accepts the key and the plaintext.
    Reads the given key and performs actions embedded in key on to the plaintext.
    Once key has been fully read and executed, the ciphertext will be returned.
"""
def encrypt(key: str, plaintext: str) -> str:
    # Convert key to a list for easier reading
    keyEntries = list(key) 

    # Blockify substitution array to allow for manipulation
    subMapBlocks = blockify("".join(SUBSTITUTION_MAP), False)

    #Blockify plaintext
    plaintextBlocks = blockify(plaintext, True)
    cipherText =""

    # Encrypt each block
    for i in range (len(plaintextBlocks)):
        # Read each key entry pair
        for j in range (0,len(keyEntries),2):
            action = keyEntries[j]
            cycles = int(keyEntries[j+1])

            match action:
                case "A":
                    # Rotate substitution letters
                    for k in range(len(subMapBlocks)):
                        subMapBlocks[k] = rotate_right(subMapBlocks[k],cycles)
                    
                    plaintextBlocks = apply_substitution(subMapBlocks,plaintextBlocks)

                case "B":
                    swap_block(subMapBlocks,cycles)
                    plaintextBlocks = apply_substitution(subMapBlocks,plaintextBlocks)

                    
                case "C":
                    for k in range(len(subMapBlocks)):
                        subMapBlocks[k] = fib_swap(subMapBlocks[k],cycles)
                    plaintextBlocks = apply_substitution(subMapBlocks,plaintextBlocks)

                case "D":
                    
                    length = len(subMapBlocks)
                    temp = subMapBlocks.copy()
                    subMapBlocks[cycles%length], subMapBlocks[(cycles+1)%length] = multi_fib_swap(temp[cycles%length],temp[(cycles+1)%length],cycles)
                    plaintextBlocks = apply_substitution(subMapBlocks,plaintextBlocks)
                    
                case "E":
                    for k in range(len(plaintextBlocks)):
                        plaintextBlocks[k] = rotate_right(plaintextBlocks[k],cycles)
                    
                    
                case "F":
                    swap_block(plaintextBlocks,cycles)
                    
                case "G":
                    for k in range(len(plaintextBlocks)):
                        plaintextBlocks[k] = fib_swap(plaintextBlocks[k],cycles)
                    
                    
                case "H":
                    length = len(plaintextBlocks)
                    temp = plaintextBlocks.copy()
                    plaintextBlocks[cycles%length], plaintextBlocks[(cycles+1)%length] = multi_fib_swap(temp[cycles%length],temp[(cycles+1)%length],cycles)
                    
                case _:
                    print("Something went wrong reading the key")
    
    cipherText = "".join(plaintextBlocks)
    return cipherText 

def apply_substitution(subBlocks: list, blocks: list) -> list:
    alphabet = list(ALPHABET)
    substitutions = list("".join(subBlocks))
    text = list("".join(blocks).lower())
    
    # Create map
    map = dict(zip(alphabet,substitutions))
    converted = []

    # Substitute the chars
    for char in text:
        converted.append(map.get(char,"?"))
    
    # Blockify
    result = "".join(converted)
    newBlocks = blockify(result, True)
    return newBlocks


"""
    Decryption function, accepts the key and the ciphertext.
    Reads the given key and performs actions embedded in the key on to the ciphertext.
    Calls a utility function to reconstruct the substitution alphabet before beginning decryption.
    Once key has been fully read and executed, the plaintext will be returned
"""
def decrypt(key: str, ciphertext: str) -> str: 
    ciphertext_blocks = blockify(ciphertext, False)
    sub_blocks = blockify("".join(reconstruct_substitution_alphabet(key, len(ciphertext_blocks))), False)
    keyEntries = list(key)

    # Decrypt each block
    for i in reversed(range(len(ciphertext_blocks))):
        # Read each key entry pair backwards
        for j in range(len(keyEntries)-2, -1, -2):
            action = keyEntries[j]
            cycles = int(keyEntries[j+1])

            match action:
                case "A":
                    ciphertext_blocks = reverse_substitution(sub_blocks,ciphertext_blocks)
                    # Rotate substitution letters
                    for k in range(len(sub_blocks)):
                        sub_blocks[k] = rotate_left(sub_blocks[k],cycles)
                    

                case "B":
                    ciphertext_blocks = reverse_substitution(sub_blocks,ciphertext_blocks)
                    swap_block(sub_blocks,cycles)
                    

                case "C":
                    ciphertext_blocks = reverse_substitution(sub_blocks,ciphertext_blocks)
                    for k in range(len(sub_blocks)):
                        sub_blocks[k] = reverse_fib_swap(sub_blocks[k],cycles)
                    
                case "D":
                    ciphertext_blocks = reverse_substitution(sub_blocks,ciphertext_blocks)
                    length = len(sub_blocks)
                    temp = sub_blocks.copy()
                    sub_blocks[cycles%length], sub_blocks[(cycles+1)%length] = reverse_multi_fib_swap(temp[cycles%length],temp[(cycles+1)%length],cycles) 
                    
                case "E":
                    for k in range(len(ciphertext_blocks)):
                        ciphertext_blocks[k] = rotate_left(ciphertext_blocks[k],cycles)
                    
                case "F":
                    swap_block(ciphertext_blocks,cycles)
                    
                case "G":
                    for k in range(len(ciphertext_blocks)):
                        ciphertext_blocks[k] = reverse_fib_swap(ciphertext_blocks[k],cycles)
                    
                case "H":
                    length = len(ciphertext_blocks)
                    temp = ciphertext_blocks.copy()
                    ciphertext_blocks[cycles%length], ciphertext_blocks[(cycles+1)%length] = reverse_multi_fib_swap(temp[cycles%length],temp[(cycles+1)%length],cycles)
                    
                case _:
                    print("Something went wrong reading the key")

    plaintext_blocks = list(ciphertext_blocks)
    #remove the padding before returning plaintext
    return "".join(plaintext_blocks).rstrip("x")

def reverse_substitution(subBlocks: list, blocks: list) -> list:
    alphabet = list(ALPHABET)
    substitutions = list("".join(subBlocks))
    text = list("".join(blocks).lower())

    # Reversed mapping
    map = dict(zip(substitutions, alphabet))
    converted = []

    for char in text:
        converted.append(map.get(char, "?"))

    result = "".join(converted)

    return blockify(result, False)

"""
    Utility function, accepts the key and block count and reconstructs the final substitution alphabet.
    Used for decrypting ciphertext.
    Since the substitution alphabet is continously modified across all blocks during encryption, 
    the final substitution alphabet is required before decryption can occur.
"""
def reconstruct_substitution_alphabet(key: str, blocks: int) -> list: 
    # Convert key to a list for easier reading
    keyEntries = list(key) 

    # Blockify substitution array to allow for manipulation
    subMapBlocks = blockify("".join(SUBSTITUTION_MAP), False)
    for i in range (blocks):
        # Read each key entry pair
        for j in range (0,len(keyEntries),2):
            action = keyEntries[j]
            cycles = int(keyEntries[j+1])

            match action:
                case "A":
                    # Rotate substitution letters
                    for k in range(len(subMapBlocks)):
                        subMapBlocks[k] = rotate_right(subMapBlocks[k],cycles)
                case "B":
                    swap_block(subMapBlocks,cycles)
                case "C":
                    for k in range(len(subMapBlocks)):
                        subMapBlocks[k] = fib_swap(subMapBlocks[k],cycles)
                case "D":
                    length = len(subMapBlocks)
                    temp = subMapBlocks.copy()
                    subMapBlocks[cycles%length], subMapBlocks[(cycles+1)%length] = multi_fib_swap(temp[cycles%length],temp[(cycles+1)%length],cycles)

    return list("".join(subMapBlocks)) 

#Fibonacci Swap Overview: 
"""
    Accepts a block to swap characters in, and the amount of cycles to swap letters for. 
    Iterates through the list and with each iteration increments a fibonacci number,
    Swaps letter in position i with letter in fibonacci % BLOCK_LENGTH  
"""
def fib_swap(block: str, cycles: int) -> str:
    fib_prev = 0
    fib = 1
    block = list(block)
    length = len(block)
    # Swap all characters in a block cycles amount of times
    for i in range(cycles):
        for j in range(length):
            fib_pos = fib % length
            block[j], block[fib_pos] = block[fib_pos], block[j]
            # Increment fibonacci sequence
            fib_prev, fib = fib, fib + fib_prev 
    return "".join(block) 

def reverse_fib_swap(block: str, cycles: int) -> str:
    block = list(block)
    # Reconstruct the swapping sequence
    swaps = reconstruct_fib_sequence(cycles, len(block))
    # Reverse swaps 
    for swap in reversed(swaps):
        block[swap.i], block[swap.j] = block[swap.j], block[swap.i]
    return "".join(block) 

# Utility function reconstructs the swapping sequence executed by fib_swap
def reconstruct_fib_sequence(cycles: int, length: int) -> list:
    fib_prev = 0
    fib = 1 
    swaps = []
    for i in range(cycles):
        for j in range(length):
            fib_pos = fib % length
            swaps.append(Swap(j,fib_pos))
            fib_prev, fib = fib, fib + fib_prev 
    return swaps 


#Multi Fibonacci Swap Overview: 
"""
    Follows the same logic as fib_swap, except that this function will accept two blocks, and swap letters between blocks instead of within itself.
    Returns a tuple containing the two modified blocks
"""
def multi_fib_swap(block1: str, block2: str, cycles: int) -> tuple[str,str]:
    fib_prev = 0
    fib = 1
    first_block = list(block1)
    second_block = list(block2)
    length = min(len(block1),len(block2))
    # Swap all characters in a block cycles amount of times
    for i in range(cycles):
        for j in range(length):
            fib_pos = fib % length
            first_block[j], second_block[fib_pos] = second_block[fib_pos], first_block[j]
            # Increment fibonacci sequence
            fib_prev, fib = fib, fib + fib_prev 
    
    return (
        "".join(first_block),
        "".join(second_block)
    )

def reverse_multi_fib_swap(block1: str, block2: str, cycles: int) -> tuple[str,str]:
    first_block = list(block1)
    second_block = list(block2)
    length = min(len(block1), len(block2))
    # Reconstruct the swapping sequence
    swaps = reconstruct_fib_sequence(cycles, length)
    # Reverse swaps 
    for swap in reversed(swaps):
        first_block[swap.i], second_block[swap.j] = second_block[swap.j], first_block[swap.i]
    return (
        "".join(first_block),
        "".join(second_block)
    ) 

#Rotate letters 
def rotate_right(block: str, rotations: int) -> str:
    result = list(block)
    chars = list(block)
    for i in range(len(block)):
        result[i] = chars[(i-rotations)%len(block)] 
    return "".join(result)


def rotate_left(block: str, rotations: int) -> str: 
    result = list(block)
    chars = list(block)
    for i in range(len(block)):
        result[i] = chars[(i+rotations)%len(block)] 
    return "".join(result)

#Swap blocks
def swap_block(blocks: list, pos: int):
    blocks[0], blocks[pos%len(blocks)] = blocks[pos%len(blocks)], blocks[0]

#Block creation and padding
def blockify(plaintext: str, applyPad: bool): 
    increment = 0
    blocks = [] 
    while True: 
        if(increment+BLOCK_LENGTH < len(plaintext)):
            blocks.append(plaintext[increment:increment+BLOCK_LENGTH])
        else:
            blocks.append(pad(plaintext[increment:increment+BLOCK_LENGTH], applyPad))
            break
        increment+=BLOCK_LENGTH
    
    #check that we have at least 2 blocks, if not add a padded block
    #2 blocks are required since multiple actions require swapping between blocks 
    if len(blocks) < 2: 
        blocks.append("x" * BLOCK_LENGTH)
    return blocks 

def pad(text: str, applyPad: bool):
    if applyPad:
        result = text.ljust(BLOCK_LENGTH,'x')
    else:
        result = text
    return result 


# Optional CLI
if len(sys.argv) > 1 and sys.argv[1] == "True":
    while True:
        print("Enter 1 to generate a key, 2 to encrypt text, 3 to decrypt text, 4 to exit")
        choice = input()
        match choice:
            case "1":
                print(generate_key())
            case "2":
                print("Enter the key you want to use for encryption")
                key = input()
                print("Enter the text you want to encrypt")
                plaintext = input()
                print("Encryption Output:", "|" + encrypt(key, plaintext) + "|")
            case "3":
                print("Enter the key you want to use for decryption")
                key = input()
                print("Enter the text you want to decrypt")
                ciphertext = input()
                print("Decryption Output:", "|" + decrypt(key, ciphertext) + "|")
            case "4":
                break
            case _:
                print("Invalid choice, please try again")
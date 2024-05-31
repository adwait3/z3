# sonda
```
import ctypes
import platform
from z3 import *

# Detect the operating system
if platform.system() == 'Linux':
    libc = ctypes.CDLL('libc.so.6')
elif platform.system() == 'Windows':
    libc = ctypes.CDLL('msvcrt.dll')
else:
    raise OSError("Unsupported operating system")

# Declare the functions we'll use
libc.srand.argtypes = [ctypes.c_uint]
libc.rand.restype = ctypes.c_int

# Create a Z3 solver instance
solver = Solver()

# Declare the seed variable
seed = Int('seed')

# Add the constraints for seed
solver.add(seed % 17 == 0)
solver.add(seed <= 20)
solver.add(seed > 0)

# Check for a valid seed
if solver.check() == sat:
    model = solver.model()
    seed_value = model[seed].as_long()
    print(f"Valid seed found: {seed_value}")

    # Now, set the random seed using libc's srand and generate the sequence
    libc.srand(seed_value)
    ptr = [2 * seed_value + libc.rand() % (5 * seed_value)]
    for i in range(1, seed_value):
        v5 = ptr[i - 1]
        ptr.append(v5 + libc.rand() % 94 + 33)

    # Create a new Z3 solver for the string s
    solver2 = Solver()
    s = [Int(f's[{i}]') for i in range(seed_value)]

    # Add the constraints for the string s
    for j in range(seed_value):
        v9 = Sum(s[:j+1])
        solver2.add(v9 == ptr[j])

    # Add the constraints for s to be valid ASCII characters
    for i in range(seed_value):
        solver2.add(s[i] >= 0x20, s[i] <= 0x7E)

    if solver2.check() == sat:
        model2 = solver2.model()
        s_value = ''.join(chr(model2[s[i]].as_long()) for i in range(seed_value))
        print(f"Valid string found: {s_value}")
        print(f"flag{{{s_value}}}")
    else:
        print("No valid string found")
else:
    print("No valid seed found")
```

output

```
Valid seed found: 17
Valid string found: +!@^\L<_TVRvJ]m[s
flag{+!@^\L<_TVRvJ]m[s}
```

___________________________________________________________________________________________________

# lock code

```
from z3 import *

# Given random values and seed
rands = [
    1227918265, 3978157, 263514239, 1969574147, 1833982879,
    488658959, 231688945, 1043863911, 1421669753, 1942003127,
    1343955001, 461983965, 602354579, 726141576, 1746455982,
    1641023978, 1153484208, 945487677, 1559964282, 1484758023
]
seed = 17

# Initialize the Z3 solver
s = Solver()

# Declare flag and ptr arrays
flag = [BitVec(f"flag_{i}", 8) for i in range(seed)]
ptr = [BitVec(f"ptr_{i}", 32) for i in range(seed)]

# Add constraints for ptr array
s.add(ptr[0] == 2 * seed + rands[0] % (5 * seed))
for i in range(1, seed):
    s.add(ptr[i] == ptr[i-1] + rands[i] % 94 + 33)

# Add constraints for flag values
for j in range(seed):
    v9 = Sum([ZeroExt(24, flag[k]) for k in range(j+1)])
    s.add(ptr[j] == v9)

# Check for satisfiability and print the model if it exists
if s.check() == sat:
    model = s.model()
    flag_value = ''.join([chr(model[flag[i]].as_long()) for i in range(seed)])
    print(f"Valid flag: flag{{{flag_value}}}")
else:
    print("No solution found")
```

output

```
Valid flag: flag{6n|L0V"6>f\$JE{uY}
```

_____________________________________________________________________________________________________________________


# custom crypto

```
from z3 import *

# Given encrypted values
encrypted_values = [
    28, 24, 1, 9, 9, 19, 93, 93, 94, 2, 26, 13, 6, 92, 61, 11,
    15, 39, 91, 91, 20, 28, 54, 8, 17, 89, 23, 61
]

# Initialize Z3 solver
solver = Solver()

# Number of characters in the encrypted message
num_chars = len(encrypted_values)
key_size = 4

# Create BitVec variables for the encrypted and decrypted characters
enc = [BitVec(f"enc_{i:02}", 8) for i in range(num_chars)]
dec = [BitVec(f"dec_{i:02}", 8) for i in range(num_chars)]
key = [BitVec(f"key_{i:02}", 8) for i in range(key_size)]

# Add known prefix constraint to guide the solver
known_prefix = 'pwned'
for i, v in enumerate(known_prefix):
    solver.add(dec[i] == ord(v))

# Add constraints for encryption/decryption relationship
for i in range(num_chars):
    chunk = i // key_size
    offset = i % key_size
    solver.add(enc[i] == encrypted_values[i])
    solver.add((dec[i] + chunk) ^ key[offset] == enc[i])
    # Ensure the decrypted values are within the ASCII printable range
    solver.add(dec[i] >= 32, dec[i] <= 126)

# Check for a solution
if solver.check() == sat:
    model = solver.model()
    # Extract and sort the solution
    flag_chars = [chr(model[dec[i]].as_long()) for i in range(num_chars)]
    flag = ''.join(flag_chars)
    print(f"Flag: {flag}")
else:
    print("No solution found")
```

output

```
Flag: pwned{100ks_g0Od_D03snT_w0rK

```

________________________________________________________________________________________________________________________

# math gen me 

```
from z3 import *

# The given license key
license_key = "04b2fc467e104c0c610e3bf0a009a9f3621905df1997ce0b6cd6a3ea68af4d4deaaf024906f7b259ba32035ac4dad586"
license_bytes = [int(license_key[i:i+2], 16) for i in range(0, len(license_key), 2)]

# Initialize Z3 solver
solver = Solver()

# Variables for the password characters
password_length = 48
password = [BitVec(f's{i}', 8) for i in range(password_length)]

# Add constraints that password characters are in ASCII range (printable characters)
for p in password:
    solver.add(p >= 32, p <= 126)

# Apply the transformations for each block of 4 characters
for i in range(0, password_length, 4):
    s0, s1, s2, s3 = password[i:i+4]

    v0 = 33 * s3 + 89 * s2 + 103 * s1 + 66 * s0
    v1 = 73 * s0 - 125 * s1 - 103 * s2 + 51 * s3
    v2 = 113 * s1 + s3 + 54 * s0 + 8 * s2
    v3 = 25 * s2 + 23 * s3 + 119 * s0 + 3 * s1

    solver.add(v0 & 0xFF == license_bytes[i])
    solver.add(v1 & 0xFF == license_bytes[i+1])
    solver.add(v2 & 0xFF == license_bytes[i+2])
    solver.add(v3 & 0xFF == license_bytes[i+3])

# Check if the solution exists and get the model
if solver.check() == sat:
    model = solver.model()
    decoded_password = ''.join(chr(model[p].as_long()) for p in password)
    print(f"Password: {decoded_password}")
else:
    print("No solution found")
```
output

```
Password: pwned{0i_m4t3_y0u_g0t_a_l0ic3nse_f0r_th4t_m4th?}
```

_______________________________________________________________________________________________________________________________________________

# server

```
from z3 import *

# Hexadecimal arrays as given
hex_arrays = [
    "0D 02 0B 13 1B 09 0A 00 10 06 07 1A 05 12 04 19 11 0E 17 16 0F 1C 1D 18 08 15 01 03 1F 0C 1E 14",
    "A8 5F 43 DF 90 15 A2 F5 77 48 49 6C 67 20 0E CD B6 C8 4A E7 89 2F A1 A6 E8 B7 E1 C6 58 A9 D4 5A 4D 9E 34 05 53 C2 76 D3 C5 B3 BF C9 AF 98 25 68 D9 2D E6 65 D7 59 D6 0A 31 8F 99 AA 7C C0 35 B5 ED 4B EB D5 8E 6B 9D 37 2E 62 0F 07 9B 87 B8 BD DE 69 C7 CF 66 46 60 04 D0 A7 F8 70 7E FA 9A 03 08 C4 F6 8B 79 33 23 DD DA C1 13 CE 16 EE 93 63 12 6F 83 0D 71 64 4C 51 00 BA EF 95 6E 22 E5 94 30 FB 14 41 7A 1C 2A 56 B9 38 42 F0 44 F3 F2 9F 52 4E D8 CB 24 32 BE 0C A3 09 85 01 1D A5 28 45 F4 47 CC AE C3 AB A0 92 72 57 AC 3E E3 B4 74 1B 81 4F DC 2B 50 02 27 B2 6D F1 54 FE 80 5E 3B 36 E2 FF 11 EA FD 1A 97 86 26 73 B1 D2 3A 1E 5D 39 7F 1F A4 91 5C 55 EC E4 29 8C F7 7D 18 82 BC 2C 75 40 BB 17 8D F9 D1 E9 0B 7B 10 CA 6A FC 19 3C 8A B0 AD 21 96 5B 06 61 3D 3F 88 78 DB 84 9C E0",
    "42 33 21 68 00 00 00 00 00 00 00 00 00 00 00 00",
    "50 21 50 EB 86 B0 44 65 4F 3E 44 0D 41 EA A2 EB 13 E4 B2 0C 4F FD F6 9E C9 30 45 0D 54 30 D7 11",
]

# Convert hex strings to integer arrays
arrays = [[int(x, 16) for x in arr.split()] for arr in hex_arrays]

# Step 1: XOR arrs[3] with arrs[2] repeated every 4 bytes
intermediate_result = [arrays[3][i] ^ arrays[2][i % 4] for i in range(32)]

# Step 2: Create a reverse lookup table for arrs[1]
reverse_lookup = {v: k for k, v in enumerate(arrays[1])}

# Step 3: Apply reverse lookup to the intermediate result
mapped_result = [reverse_lookup[v] for v in intermediate_result]

# Step 4: Create the final result by reordering according to arrs[0]
final_result = [0] * 32
for i in range(32):
    final_result[arrays[0][i]] = mapped_result[i]

# Convert final result to characters and join to form the decrypted password
decrypted_password = ''.join(chr(f) for f in final_result)

print("Decrypted password:", decrypted_password)

```

output

```
Decrypted password: sup3r_s3cr3t_p4ssw0rd_unbr3ak4bl
```

____________________________________________________________________________________________________________________________

# sweet

```
from z3 import *

def find_solution():
    # Iterate over possible input lengths from 1 to 31
    for input_len in range(1, 32):
        solver = Solver()
        input_vars = [BitVec(f"i_{i}", 8) for i in range(input_len)]
        output = BitVecVal(0, 64)

        # Compute the output based on the input variables
        for var in input_vars:
            output = (output + ZeroExt(64 - 8, var)) << 1

        # Add the constraint that the output should match the given value
        solver.add(output == 0x2d64a)

        # Check if a solution exists
        if solver.check() == sat:
            model = solver.model()
            solution = sorted([(d, model[d]) for d in model], key=lambda x: str(x[0]))
            # Convert the solution to a hexadecimal string
            flag = "".join([f"{model[var].as_long():x}" for var in input_vars])
            return flag

    return None

# Print the found solution
print(find_solution())

```

output

```
77ffeff5fd99cdbffb
```

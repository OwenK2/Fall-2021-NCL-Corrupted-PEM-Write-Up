# Reconstructing a Corrupted PEM File
Write up for a problem I solved for the [2021 Fall NCL](https://cyberskyline.com/hosted_events/ncl-fall-2021). I competed with fellow students as part of the the SDSU Cyber Defense Team. In this problem you were given a PEM file with large sections of the data redacted. The goal was to reconstruct the PEM file using data that was not redacted.

Author: Owen Kuhn ([@OwenK2](https://github.com/OwenK2))

## The Problem

The goal is to access a flag stored in `/root/flag.txt` however to do so we need root access.
All we are given is `filecorrupted.pem`. This file is an RSA private key file with several large
sections of corrupted data, in fact over half of the data is corrupted which is represented in the
file as large chunks of `o`.

We can infer from this that the goal is to reconstruct the PEM file and somehow use that to
escalate to root to view the flag.

## Understanding the format

PEM files follow the `ASN.1 DER` format and are base64 encoded, therefore we will need to
understand this format to get as much information out of the corrupted file as possible. Below
is the format for RSA. As you can see there are several integers within the binary data that we
will try to extract. It is important to note that existing tools will not work on the corrupted file
because the corruption is too extensive.

```
PrivateKeyInfo ::= SEQUENCE {
	version Version,
	privateKeyAlgorithm AlgorithmIdentifier ,
	privateKey PrivateKey,
	attributes [0] Attributes OPTIONAL
}
RSAPrivateKey ::= SEQUENCE {
	version           Version,
	modulus           INTEGER,  -- n
	publicExponent    INTEGER,  -- e
	privateExponent   INTEGER,  -- d
	prime1            INTEGER,  -- p
	prime2            INTEGER,  -- q
	exponent1         INTEGER,  -- d mod (p-1)
	exponent2         INTEGER,  -- d mod (q-1)
	coefficient       INTEGER,  -- (inverse of q) mod p
	otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

The ANS.1 DER format is a way of representing data in a compact binary fashion. It is pretty
complicated but for our purposes we only need to know how to find `INTEGER`s. In DER integers
have a type of `0x02`. Below is a figure describing how data is represented in DER.

| Type (1 byte) | HL (1 byte) | Length (optional n bytes) | Data (m bytes) |
|---------------|-------------|---------------------------|----------------|

The complication arises around `HL` and `Length`. The 2 most significant bits of `HL` describe the class and the lower 6 bits generally describe the length of the data. However if the length of the data cannot be represented in 6 bits then the optional length field must be used. In this case `HL` describes the length of the length variable. And the length describes the length of the data...  

confusing right. We can look at the MSB of `HL` to determine if the optional length is used.  

- EX. `1000 0010` = Optional length is 2 bytes which describes length of data  
- EX. `0000 1100` = No optional length field; data is 12 bytes long

## Decoding the format

The next step is to try to pull all of the values we can out of the corrupted PEM file. To do this we
need to know where those values are located in the binary data. The first step is to convert the
base64 into hex since that is easier to work with. The next step is to loop through the bytes of
the PEM file and try to locate all of the integers we can. Below is the code to find integers in the
PEM file (after it is base64 decoded into bytes). However we cannot just run this on the given
file because it is so corrupted. So first lets make our own PEM file with random data so that we
can find where the integers are. Once we find the locations of the integers we can just get those
“chunks” of data from the corrupted file.

To make our own `openssl genrsa -out testpem.pem 4096`
(FYI I found the length of $4096$ by trying increasing powers of $2$ until the number of lines
matched the corrupted file)

```python
testpem = bytes.fromhex("...") # binary data from testpem.pem
pem = bytes.fromhex("...")     # binary data from corrupted.pem
chunks = []
i = 0
while i < len(testpem):
	if testpem[i] == 0x02:
		hl = 0
		length = 0
		if (testpem[i+1] & 0x80) > 0:
			hl = testpem[i+1] & 0x3F
			length = int.from_bytes(testpem[i+2:i+hl+2], byteorder='big')
		else:
			length = testpem[i+1] & 0x3F
		chunks.append((i+2+hl, i+2+hl+length))
		print(testpem[i+2+hl:i+2+hl+length].hex())
		print()
		i += hl + length + 2
	else:
		i += 1

print(chunks)
```

This code will output all of the locations of the integers in “chunks” and it will also print the
actual hex data that we are extracting. This is important because we want to make sure the
code is working. We can now run `openssl asn1parse -in testpem.pem`.

This will automatically decode the DER format of our so we can compare our values. This
confirms that our program is working (I also realized this command gives us the start positions
of the integers which could have been used instead of writing my own program but oh well it
was too late at this point).

Now that we have the areas where the data is actually located we can pull these chunks out of
the corrupted file giving us the following variables... Remember these are in the order defined
above in the `RSAPrivateKey Sequence`.

```
009ca79d2d2b5cb6b06536fe2b0fe606a8e9676a78627354c4ec671f0b9c6c5e171988d827b6ff8ceab2b8d7de96c84ccc4711a4665538c
93afdf038ffdce0eb6a1d75322abd1432aa5b0c729cafb79e18540cc833f6d441beb536718162612727de29dc71d827c14aff67ea82d8b0
b6fabb385fec83e3fb33f1143ee4ecfccebaf1757fe1148a53ec9ce5c431eab23064d1a1bc3b6e48ccdca4431bcad0a9cbcd480e63d9d89
213bfe7ce83ce0c557574ab8526faf61a5bf067d433495d2cb05f2b50f8d4f5e59cda5698b1024ba58e33d106fa2edfd80987c466071c06
8e30ee3d15e6fc1cb242931770de36bdd42b937eada4e804fe5e9b1aac6c42adae0c18d583a513e7203b9f6f2a8cda100ce81032511b000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000

000000

000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000

000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000dd8c516b1906ebc550f093

00c2c95e64c853063d982ae13287bbe747db57e803bae644ecf195cf75d465f8bed187986358601ff6c241944bc8336980a0cb3549b325f
4115ea7bc504139873f5415651eb5785e6bd05c945c87916ba21e133ac2c45158f229a333b0ead5ec68bcfa55e8c4128a4c4dd062edde5d
24d6f35200188a1350abc9917622612d5eab0d80b4fabec99c7a093f21eb36783bc6488da3ed5b641a24c86490ebf72628dc3a78fc82f1d
22964a4cb2f65b4d7077e2b512d90f5908eb0ec70d6a559ce8661bdd29f007ba522ff06efe6d9fa6ac0d940531eeea2541025ca4300be6a
63ca79daa26db53fee8b7832cc04fc16ab92f152cc563fd1091d7350ab15b0bdd8eeef
7beaacf420ed84b2553e7bf620d1231c56bc767476fa74fc2b4ec8fd63c2c15498c695851ff8bb3c8e049a3fcbc421ca48fd3e5261acb7a
04171f1418099978c30b797a4809a9ab28bada43812dbdff65907c73416f31e3cf2a42c2bab34d87f6659a311e4b7acae034bb57c725053
55ebe4fe31f079bbec52eaa89567707e8508c157e81b0ef5d83d26b878d5b9890d67884cd5b3fecdbade29db3d4aa37dbe5b58884e80f40
10855b831760cd9bcabc25edbfeacc4328d24525461feafc61f3cb6b23aa9f9e10b4cfd766dd0bdf352a298974b38dcd6e1b688eb2f843f
1ad3748f35a1f0bdc4c14b11619fad9bd8d169ab2ed0df08bb8cc18e15a950608ffb

4ea1ab9153acf05ffd0592532ba816fd52f6719acfe01502f1a3605458a1b1809664fe875c2db1b90000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000

000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
00000000000000000000000000000000000000000000000000000000000000000000
```

## Looking at what we found + math
So based on the above discoveries we now have some of the upper bits of $n$, none of $e$, none of $d$, some of the lower bits of $p$, all of $q$, all of $d \mod (p-1)$, some of $d \mod (q-1)$, and none of the rest. Let's call the $d \mod (p-1)$ and $d \mod (q-1)$ and $dq$ respectively. It's about time we figure out how these variables are actually used. RSA depends on prime factorization of massive numbers, since this is a hard thing for computers to accomplish in a short period of time. So what we really need is to find both $p$ and $q$ prime factors. In order to find the rest of $p$ we will have to use brute force. In order to make the brute force possible we have to use some math, which I won't describe in detail and will instead just provide the important formula.

$$
p = \frac{e \cdot dp - 1}{k_p} \text{ where } 3 \leq k_p < e
$$

Notice that we are missing $e$, however a common choice for $e$ is $65537$ so we can guess that that is what was used for our corrupted key. If this was not the case we could easily brute force $e$ as well. So now all we have to do is iterate through all of the values of $k_p$ until we find a prime number whose lower bits match the ones we know. This gives us the value of $p$.

```python
import sympy
e = 65537
upper_n = ...
lower_p = 0xdd8c516b1906ebc550f093
q = ...
dp = ...

p = 0
for kp in range(3, e):
    p_mul = dp * e - 1
    # Only need to continue if p_mul is divisible by kp
    if p_mul % kp == 0:
        p = (p_mul // kp) + 1
        # Check if number is prime and ends with our known lower bits
        if sympy.isprime(p) and hex(p).endswith(hex(lower_p)[2:]):
        	print(hex(p))
```

## Math to recover the PEM file
At this point we can calculate the rest of the variables we need to create a new pem file. I used
the Crypto library to generate the RSA PEM file from $n$, $e$, $d$, $p$, and $q$.

\begin{align}
n &= p \cdot q\\
\phi &= (p-1) \cdot (q-1)\\
d &= e^{-1} \mod \phi
\end{align}

## We have the PEM file... now what?
At this point we have the file completely reassembled and de-corrupted but how can we use it to
become root? Well the solution is to ssh into the root user from our unprivileged user, using the
pem file.

```bash
ssh -i fixed.pem root@127.0.0.1
```

This logs us in as root and now we can simply run

```bash
cat /root/flag
```

to get the flag.

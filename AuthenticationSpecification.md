# CoreRF Protocol Specification - Authentication

## Introduction

This document outlines the process specification for sharing authentication
keys and using the key to authenticate the phone to a device to gain access
to underlying application capabilities

## Background

### Diffie-Hellman exchange
The Diffie-Hellman exchange (DHE) process is a way of generating a shared
secret between two parties in such a way that the secret can't be seen by
observing the communication.  This is useful in the CoreRF context because
BLE traffic can be sniffed by a third party.  Even if the third party recorded
the traffic to analyze later, it is extremely difficult to determine the
shared secret key.  The basic flow is as follows:

 1. Alice comes up with two prime numbers `g` and `p` and tells Bob what they are.
 2. Bob then picks a secret number `a`, but doesn't tell anyone.  Instead Bob 
 computes `g ^ a modulus p` and sends the result back to Alice (aka `A` since
 it was derived from `a`
 3. Alice performs the same process as step 2, but Alice's secret number is
 `b` and computes `g ^ b modulus p` to derive `B`.
 4. Now Bob takes the number Alice sent him (`B`) and does the exact same operation
 with it.  This is `B ^ a modulus p`
 5. Alice does the same operation with the result Bob sent her, or `A ^ b modulus p`

The "magic" here is that the answer Alice got in step 5 is _the same number_
(`shared secret`) as you got in step 4.  However, because `a` and `b` were
never transmitted over the wire, it is virtually impossible to calculate `shared secret`

### Diffie-Hellman variants

The strength of DHE can be improved by two strategies.  First, increasing the
size of `p` increases the computational power required by an observer to brute
force calculate the `shared secret` from `A` and `B`.  The downside of this is
larger numbers may be too large for device hardware to handle.  It is left up
to the development of a particular device to determine the largest `p` possible
that the device can feasible use.

The second strategy, a variant of Diffie-Hellman, called _Elliptical Curve
Diffie-Hellman_ (ECDHE).  This variant uses elliptical curve math to increase
the difficulty of discovering the key.  However, the device hardware may not 
be able to handle this, so it is not used in this specification

### IETF Modular Exponential Group (MODP)

To help internet services utilize DHE securely, the IETF has published several
pairings of `p` and `g` that have been researched for their security.  The IETF
published these pairings, or Modular Exponential Groups, in RFC 2409, 3526
and 5114.  The main difference between the MODP groups is the size of `p`, which
increases the strength of DHE for larger values of `p`.  The smallest `p` is 768 bits.


## Key sharing

At the device imprinting stage, the phone and device need to agree upon a private
shared key for the phone to use later for authentication purposes.  To mitigate
possibly eavesdropping, the Diffie-Hellman Key Exchange process will be used
to generate the private shared key.  This process requires two application request
messages named `Start Auth Key Generation` and `Exchange Public Key`.  A sample
flow followed by detailed explanation of the process is below:

 1. Phone -> Start Auth Key Generation Request {no payload} -> Device
 2. Phone <- Start Auth Key Generation ACK { MODP group } <- Device
 3. Phone -> Exchange Public Key Request { phone's public key } -> Device
 4. Phone <- Exchange Public Key ACK { device's public key } <- Device
 5. Hash private shared key

#### Step 1 - Phone initiates Auth Key Generation flow

This step is performed once during the device imprinting phase.  The phone
issues a `Start Auth Key Generation Request` message to the device with no payload

#### Step 2 - Device responds with MODP group to use for key generation

DHE requires using an extremely large prime number `p` and a generator `g` that
both parties need to agree upon before continuing the key exchange process.
Rather than expending the effort to come up with the needed numbers, this auth
key exchange will utilize one of these MODP groups published by the IETF ().
A MODP group is a calculated `p` and `g` pair.  The different groups defined by
the IETF vary by size of `p`, thus increasing the difficulty to discover a private
shared key from the public keys exchanged

To avoid transmitting 96+ bytes of `p` and `g` over the BLE connection, this
specification calls for the IETF MODP groups to be pre-existing on both device
and phone.  As the device hardware is the limiting factor, the device gets to
choose which MODP group will be used in DHE.  The selected IETF group identifier
will be transmitted from device to phone as the payload of the `Start Auth Key
Generation ACK`.

#### Step 3 - Phone generates public key and sends to phone

Once the MODP group has been selected, the phone randomly selects a private key
and generates the public key as per the DHE specification (`public_key = g ^ private_key % p`).
The phone then transmits the public key to the device via an `Exchange Public
Key Request` message.

#### Step 4 - Device generates a public key and sends to phone

The device generates its own public key in the same fashion as the phone did
in step 3.  Once completed, the device sends its public key back to the device
via an `Exchange Public Key ACK`

#### Step 5 - Hash private shared key

Now that both phone and device has their private keys and the other's public
key, it can generate the private shared key according to the Diffie-Hellman
specification (`private_shared_key = other_public_key ^ private_key % p`).
The resulting shared key is much larger than the needed 16 bytes for AES-128
Cipher used during device authentication.  To arrive at the needed 16 bytes,
both the phone and device will use the MD5 hashing function on the private shared
key to arrive at the authentication token.

Once finished, the phone can complete the imprinting flow.  If the device has any
issues during this stage, it should not allow the imprinting process to complete

## Phone authentication

After BLE connection to the device, the phone and device needs to authenticate
themselves to each other for the phone to gain access to sensitive functionality.
For unimprinted devices, the phone and device will use a default authentication
token that has been set in the device in the factory.  After imprinting, the phone
and device will use the authentication token generated from the `Key sharing`
section above.  A sample flow followed by detailed explanation of the process is below:

 1. Phone -> Start Authentication Request { 16 byte phone nonce } -> Device
 2. Phone <- Start Authentication ACK { encrypted 16 byte phone nonce, 16 byte device nonce } <- Device
 3. Phone -> Authentication Challenge Request { encrypted 16 byte device nonce } -> Device
 4. Phone <- Authentication Challenge ACK { no payload } <- Device

**Note**

> To prevent brute-force replay attacks, the phone and device will replace the
> first 4 bytes of the nonce with 4 random bytes prior to encrypting the nonce.
> This guarantees that the ciphertext output will not be the same for the same
> plaintext input, making it harder for attackers to determine the secret shared
> key.  When a phone or device decrypts an encrypted nonce to authenticate, it
> shall discard the first 4 bytes and only compare the final 12 bytes

 
#### Step 1 - Phone initiates Authentication flow

The phone starts off the authentication flow by generating a 16 byte nonce and
storing it locally.  Additionally, it sends that nonce to the device via a `Start
Authentication Request` message.

#### Step 2 - Device responds with nonces

Upon receiving the nonce from the phone, the device will replace the first 4 bytes
of nonce with 4 randomly generated bytes.  The device will then encrypt this new nonce
using AES-128 cipher algorithm in AES/ECB/NoPadding cipher mode.  The device will
package the encrypted new nonce with a device generated 16 byte nonce (stored locally)
and transmit both to the phone in a `Start Authentication ACK` message.

#### Step 3 - Phone encrypts device nonce

After receiving ACK from the device, the phone first decrypts the encrypted phone
nonce and compares the final 12 bytes to the final 12 bytes of its own locally stored
nonce.  If there is no match, the phone isn't connected to a valid device and should
abandon the connection.  If there is a match, the phone should replace the first 4
bytes of device nonce with 4 randomly generated bytes.  The phone will then encrypt
the device's new nonce using the same AES-128 cipher algorithm in AES/ECB/NoPadding
cipher mode.  The phone then transmits the encrypted device nonce to the device via
a `Authentication Challenge Request` message.

#### Step 4 - Device decrypts device nonce

Similar to Step 3, the device decrypts the encrypted device nonce and compares the
final 12 bytes to the final 12 bytes of the original device nonce.  If there is no
match, the phone is not authenticated and the device should not allow access to
sensitive functionality.  The device notifies the phone of this auth challenge failure
with a `Authentication Challenge NAK` message.  If there is a match, the phone is
authenticated and is granted access to sensitive functionality.  The device notifies
the phone via a `Authentication Challenge ACK` message.
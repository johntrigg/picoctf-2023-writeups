import math
import sympy
from itertools import combinations
import requests
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
#https://crypto.stackexchange.com/questions/105734/crack-rsa-with-e-and-d#comment226368_105734

def get_combinations(arr, n):
    return [list(c) for c in combinations(arr, n)]

def generateCompositeToFactor(d):
    factorThis = d*65537
    factorThis = factorThis-1
    return factorThis

c = 3259579886028188512196242819181748657620611571295925503651760707471266942964
d = 16390919850998015106959202306873122870798714448390783672799088776597368419201
e = 65537

factorThis = generateCompositeToFactor(d)
print(f"{factorThis = }") 

#run to factorDB, and put all the factors in, if it gives you 7^3, put in 7 three times. since 7 is a factor three times
factorPool = [42104078480216652208110324359,99411644228541737,47902308698466997,363361,229,179,97,37,29,3,3,3,2,2,2,2,2,2,2]
arrayLength = len(factorPool)
print(f"{arrayLength=}")

n = arrayLength + 1
primeArray = []
#run the script, but every time, decrease what's being subtracted from n by 1
iterator = 0

while iterator < arrayLength-3:
    n = n - 1
    #print("Outer loop ran")
    factorCombinations = get_combinations(factorPool, n)
 
    for potentialCombination in factorCombinations: #iterate over every combination of length n
        #print("Inner loop running")
        #print(combination)
        u = math.prod(potentialCombination) #multiply everything together
        bitsU = math.log2(u)
        #print(u)
        if 124 <= bitsU <= 128: #check if u is between 125 and 129 bits long before doing operations, to speed things up
            p = 2*u 
            p = p + 1          
            bitsP = math.log2(p)
            #print(p)
            if 127 <= bitsP <= 129: #a 128 bit prime will have a log2 of 128 plus or mins half a bit, so anything outself this range is incorrect
                isPrime = sympy.isprime(p)
                if isPrime == True:
                        #print("Prime found, enumerating.")
                        if p not in primeArray:
                            print(f"{p = }")
                            primeArray.append(p)
                        #print(combination)
    iterator = iterator + 1

print(primeArray)

choose2 = 2

potential_pairs = get_combinations(primeArray, choose2) #grab every combination of 2 numbers from the pool of primes

for pairCombination in potential_pairs: #try to recreate the private key. if we can, p and q are correct
    n = math.prod(pairCombination)
    p = pairCombination[0]
    q = pairCombination[1]
    n=p*q
    phi_n = (p-1)*(q-1)
    combined_d = inverse(65537, phi_n) #textbook rsa generation to derive n, phi(n), and d from p and q
    if combined_d == d:  #check if the d of the pair, is equal to the given d. if they are, then we decode the ciphertext and get the plaintext
        print("GG.")
        plaintext = long_to_bytes(pow(c,d,n)) #decode using d and n
        print(f"{plaintext = }")

print(f"{factorThis = }") 
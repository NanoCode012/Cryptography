## Binary Exponentiation

# https://stackoverflow.com/a/10539256/8293176
# b = b_0 + b1 * 2 + b2 * 2**2 + ... + b_k ** 2**k
# a ** b = a**b0 * (a**2)**b1 * (a**2**2)**b2 * ... * (a**2**k)**b_k
# mod c at every step
def pow_mod(x, y, z):
    "Calculate (x ** y) % z efficiently."
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1
        x = x * x % z
    return number



## Modular Exponentiation 

# https://dev-notes.eu/2019/12/Fast-Modular-Exponentiation/#:~:text=Modular%20exponentiation%20is%20used%20in%20public%20key%20cryptography.&text=You%20could%20brute%2Dforce%20this,to%20have%20any%20practical%20application.
def fast_exp(b, e, m):
    r = 1
    if 1 & e:
        r = b
    while e:
        e >>= 1
        b = (b * b) % m
        if e & 1: r = (r * b) % m
    return r

# https://www.geeksforgeeks.org/modular-exponentiation-power-in-modular-arithmetic/
def power(x, y, p) :
    res = 1     # Initialize result
 
    # Update x if it is more
    # than or equal to p
    x = x % p
     
    if (x == 0) :
        return 0
 
    while (y > 0) :
         
        # If y is odd, multiply
        # x with result
        if ((y & 1) == 1) :
            res = (res * x) % p
 
        # y must be even now
        y = y >> 1      # y = y/2
        x = (x * x) % p
         
    return res


## Inverse 


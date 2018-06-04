""" Utilities """
from petlib.ec import EcGroup



# ==================================================
# El-Gamal encryption scheme
# ==================================================
def elgamal_keygen(params):
   """ generate an El Gamal key pair """
   (G, o, g, h) = params
   d = o.random()
   gamma = d * g
   return (d, gamma)

def elgamal_enc(params, gamma, m, h):
    """ encrypts the values of a message (h^m) """
    (G, o, g, _) = params
    k = o.random()
    a = k*g
    b = k*gamma + m*h
    return (a, b, k)

def elgamal_dec(d, c):
    """ decrypts the message (h^m) """
    (a, b) = c
    return b - d*a



# ==================================================
# polynomial utilities
# ==================================================
def poly_eval(coeff, x):
	""" evaluate a polynomial defined by the list of coefficient coeff at point x """
	return sum([coeff[i] * (x ** i) for i in range(len(coeff))])

def lagrange_basis(t, o, i, x=0):
	""" generates the lagrange basis polynomial li(x), for a polynomial of degree t-1 """
	numerator, denominator = 1, 1
	for j in range(1,t+1):
		if j != i:
			numerator = (numerator * (x - j)) % o
			denominator = (denominator * (i - j)) % o 
	return (numerator * denominator.mod_inverse(o)) % o


# ==================================================
# other
# ==================================================
def ec_sum(list):
	""" sum EC points list """
	ret = list[0]
	for i in range(1,len(list)):
		ret = ret + list[i]
	return ret




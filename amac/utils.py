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
# other
# ==================================================
def ec_sum(list):
	""" sum EC points list """
	ret = list[0]
	for i in range(1,len(list)):
		ret = ret + list[i]
	return ret




""" Mac GGM scheme """
from petlib.ec import EcGroup


def setup():
	""" generate all public parameters """
	G = EcGroup()
	o = G.order()
	g = G.generator()
	h = G.hash_to_point("mac_ggm".encode("utf8"))
	return (G, o, g, h)


def keygen(params, q):
	""" mac GGM keygen """
	assert q > 0
	(G, o, g, h) = params
	sk = [o.random() for _ in range(q+1)]
	iparams = [ski*h for ski in sk[1:]]
	return (sk, iparams)


def mac(params, sk, m):
	""" compute mac GGM """
	assert len(sk) > len(m) and len(m) > 0
	(G, o, g, h) = params
	u = o.random()*g
	Hx = sk[0] + sum([sk[i+1]*m[i] for i in range(len(m))])
	u_prime = Hx*u
	sigma = (u, u_prime)
	return sigma


def verify(params, sk, m, sigma):
	""" verify mac GGM """
	assert len(sk) > len(m) and len(m) > 0
	(G, o, g, h) = params
	(u, u_prime) = sigma
	hx = sk[0] + sum([sk[i+1]*m[i] for i in range(len(m))])
	return u != G.infinite() and u_prime == hx*u

""" aMAC zero-knowledge proofs. """
from petlib.bn import Bn
from petlib.ec import EcGroup
from hashlib import sha256
from binascii import hexlify
from amac.utils import ec_sum


def to_challenge(elements):
    """ generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash = sha256(Cstring).digest()
    return Bn.from_binary(Chash)


def make_pi_prepare_issue(params, gamma, ciphertext, k, private_m):
	""" make prepare issuance proof """
	(G, o, g, h) = params
	assert len(ciphertext) == len(k) and len(ciphertext) == len(private_m)
	wk = [o.random() for _ in k]
	wm = [o.random() for _ in private_m]
	# compute the witnesses commitments
	Aw = [wki*g for wki in wk]
	Bw = [wk[i]*gamma + wm[i]*g for i in range(len(private_m))]
	# create the challenge
	(a, b) = zip(*ciphertext)
	c = to_challenge([g, h]+list(a)+list(b)+Aw+Bw)
	# create responses
	rk = [(wk[i] - c*k[i]) % o for i in range(len(wk))]
	rm = [(wm[i] - c*private_m[i]) % o for i in range(len(wm))]
	return (c, rk, rm)


def verify_pi_prepare_issue(params, gamma, ciphertext, proof):
	""" verify prepare issuance proof """
	(G, o, g, h) = params
	(c, rk, rm) = proof
	assert c and len(ciphertext) == len(rk) and len(ciphertext) == len(rm)
	(a, b) = zip(*ciphertext)
	# re-compute witnesses commitments
	Aw = [c*a[i] + rk[i]*g for i in range(len(rk))]
	Bw = [c*b[i] + rk[i]*gamma + rm[i]*g for i in range(len(ciphertext))]
	# verify challenge
	return c == to_challenge([g, h]+list(a)+list(b)+Aw+Bw)


def make_pi_issue(params, sk, iparams=None, gamma=None, c=[], b=None, bsk= None, r=None, public_m=[], u=None):
	""" make issuance proof """
	assert len(c)+len(public_m) > 0
	(G, o, g, h) = params
	(x, x0_tilde) = sk
	assert x0_tilde and len(x) > len(c)+len(public_m)

	## mixed public / private attributes
	if len(c): 
		assert iparams and gamma and b and r
		(bx, bx0_tilde) = bsk
		assert bx0_tilde and len(bx) == len(x)
		(Cx0, X) = iparams
		assert Cx0 and len(x) == len(X)+1
		(enc_a, enc_b) = zip(*c) 
		# create the witnesses
		wx = [o.random() for _ in x]
		wx0_tilde = o.random()
		wb = o.random()
		wbx = [o.random() for _ in x]
		wbx0_tilde = o.random()
		wr = o.random()
		# compute the witnesses commitments (prove knowledge of MAC's secrets)
		Aw = wx[0]*g + wx0_tilde*h
		Bw = wb*g
		Cw = wbx[0]*g + wbx0_tilde*h
		Dw = wb*Cx0
		# compute the witnesses commitments (prove of correctness of Xi's)
		Ew = [wxi*h for wxi in wx[1:]]
		Fw = [wbxi*h for wbxi in wbx[1:]]
		Gw = [wb*Xi for Xi in X]
		# compute the witnesses commitments (prove of correctness of credentials)
		t1 = [mi*g for mi in public_m]
		Hw = wr*g + ec_sum([wbxi*enc_ai for wbxi,enc_ai in zip(wbx[1:],enc_a)])
		Iw = wr*gamma + wbx[0]*g + ec_sum([wbxi*enc_bi for wbxi,enc_bi in zip(wbx[1:],list(enc_b)+t1)])
		# create the challenge
		c = to_challenge([g, h, Aw, Bw, Cw, Dw, Hw, Iw]+Ew+Fw+Gw)
		# create responses
		rx = [(wxi - c*xi) % o for (wxi,xi) in zip(wx,x)]
		rx0_tilde = (wx0_tilde - c*x0_tilde) % o
		rb = (wb - c*b) % o
		rbx = [(wbxi - c*bxi) % o for (wbxi,bxi) in zip(wbx,bx)]
		rbx0_tilde = (wbx0_tilde - c*bx0_tilde) % o
		rr = (wr - c*r) % o
		return (c, rx, rx0_tilde, rb, rbx, rbx0_tilde, rr)

	## only public attributes
	else: 
		assert u
		# create the witnesses
		wx = [o.random() for _ in x]
		wx0_tilde = o.random()
		# compute the witnesses commitments
		Aw = wx[0]*g + wx0_tilde*h
		Bw = [wxi*h for wxi in wx[1:]]
		Cw = wx[0]*u + ec_sum([wxi*mi*u for (wxi,mi) in zip(wx[1:],public_m)])
		# create the challenge
		c = to_challenge([g, h, Aw, Cw]+Bw)
		# create responses
		rx = [(wxi - c*xi) % o for (wxi,xi) in zip(wx,x)]
		rx0_tilde = (wx0_tilde - c*x0_tilde) % o
		return (c, rx, rx0_tilde)


def verify_pi_issue(params, iparams, u, u_prime, pi_issue, biparams=None, gamma=None, ciphertext=[], public_m=[]):
	""" verify issuance proof """
	assert iparams and u and u_prime and pi_issue and len(ciphertext)+len(public_m) > 0
	(G, o, g, h) = params
	(Cx0, X) = iparams
	assert Cx0 and len(X) >= len(ciphertext)+len(public_m)

	## mixed public / private attributes
	if len(ciphertext): 
		assert biparams and gamma
		(bCx0, bX) = biparams
		assert bCx0 and len(bX) == len(X)
		(t2, t3) = u_prime
		assert t2 and t3
		(c, rx, rx0_tilde, rb, rbx, rbx0_tilde, rr) = pi_issue
		(enc_a, enc_b) = zip(*ciphertext) 
		# compute the witnesses commitments (prove knowledge of MAC's secrets)
		Aw = rx[0]*g + rx0_tilde*h + c*Cx0
		Bw = rb*g + c*u
		Cw = rbx[0]*g + rbx0_tilde*h + c*bCx0
		Dw = rb*Cx0 + c*bCx0
		# compute the witnesses commitments (prove of correctness of Xi's)
		Ew = [rxi*h + c*Xi for (rxi,Xi) in zip(rx[1:],X)]
		Fw = [rbxi*h + c*bXi for (rbxi,bXi) in zip(rbx[1:],bX)]
		Gw = [rb*Xi + c*bXi for (Xi,bXi) in zip(X,bX)]
		# compute the witnesses commitments (prove of correctness of credentials)
		t1 = [mi*g for mi in public_m]
		Hw = rr*g + ec_sum([rbxi*enc_ai for (rbxi,enc_ai) in zip(rbx[1:],enc_a)]) + c*t2
		Iw = rr*gamma + rbx[0]*g + ec_sum([rbxi*enc_bi for (rbxi,enc_bi) in zip(rbx[1:],list(enc_b)+t1)]) + c*t3
		# check the challenge
		return c == to_challenge([g, h, Aw, Bw, Cw, Dw, Hw, Iw]+Ew+Fw+Gw)

	## only public attributes
	else:
		assert len(X) >= len(public_m)
		(c, rx, rx0_tilde) = pi_issue
		# re-compute the witnesses commitments
		Aw = rx[0]*g + rx0_tilde*h + c*Cx0
		Bw = [rxi*h + c*Xi for (rxi,Xi) in zip(rx[1:],X)]
		Cw = rx[0]*u + c*u_prime + ec_sum([rxi*mi*u for (rxi,mi) in zip(rx[1:],public_m)])
		# check challenge
		return c == to_challenge([g, h, Aw, Cw]+Bw)


def make_pi_show(params, iparams, m, r, z, u_prime, sigma):
	""" make credentials showing proof """
	(G, o, g, h) = params
	(_, X) = iparams
	print(m)
	assert len(X) >= len(m)
	(u, Cm, Cu_prime) = sigma
	# create the witnesses
	wr = o.random()
	wz = [o.random() for _ in m]
	wm = [o.random() for _ in m]
	# compute the witnesses commitments
	Aw = [wmi*u + wzi*h for (wmi,wzi) in zip(wm,wz)]
	Bw = wr*g + ec_sum([wzi*Xi for (wzi,Xi) in zip(wz,X)])
	# create the challenge
	c = to_challenge([g, h, Cu_prime, Bw]+Cm+Aw)
	# create responses
	rr = (wr + c*r) % o  # note the '+' sign 
	rm = [(wmi - c*mi) % o for (wmi,mi) in zip(wm,m)]
	rz = [(wzi - c*zi) % o for (wzi,zi) in zip(wz,z)]
	return (c, rr, rm, rz)


def verify_pi_show(params, iparams, sigma, pi_show, V):
	""" verify credentials showing proof """
	assert iparams and sigma and pi_show
	(G, o, g, h) = params
	(_, X) = iparams
	(u, Cm, Cu_prime) = sigma
	assert u and len(X) >= len(Cm) > 0 and Cu_prime
	(c, rr, rm, rz) = pi_show
	# re-compute the witnesses commitments
	Aw = [rmi*u + rzi*h + c*Cmi for (rmi,rzi,Cmi) in zip(rm,rz,Cm)]
	Bw = rr*g + ec_sum([rzi*Xi for (rzi,Xi) in zip(rz,X)]) + c*V
	# verify challenge 
	return c == to_challenge([g, h, Cu_prime, Bw]+Cm+Aw)










	






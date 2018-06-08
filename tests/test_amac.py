from amac.utils import *
from amac.scheme import *



def test_public_attributes():
	q = 2 # max number of attributes
	public_m = [3] * q # attributes
	params = setup()

	# generate key	
	(iparams, sk) = cred_keygen(params, q)

	# credentials issuance
	(u, u_prime, pi_issue) = blind_issue(params, sk, public_m=public_m)
	(u, u_prime) = blind_obtain(params, iparams, u, u_prime, pi_issue, public_m=public_m)

	# credentials showing	
	(sigma, pi_show) = blind_show(params, iparams, (u, u_prime), public_m=public_m)
	assert blind_verify(params, sk, iparams, sigma, pi_show)
	


def test_private_attributes():
	q = 5 # max number of attributes
	private_m = [3] * 2 # attributes
	public_m = [10] * 3 # attributes
	params = setup()
	(d, gamma) = elgamal_keygen(params) # El-Gamal keypair

	# generate key	
	(iparams, sk) = cred_keygen(params, q)

	# prepare issuance
	(c, pi_prepare_issue) = prepare_blind_issue(params, gamma, private_m)

	# credentials issuance
	(u, u_prime_tilde, pi_issue, biparams) = blind_issue(params, sk, iparams, gamma, c, pi_prepare_issue, public_m=public_m)
	(u, u_prime) = blind_obtain(params, iparams, u, u_prime_tilde, pi_issue, biparams=biparams, d=d, 
		gamma=gamma, c=c, public_m=public_m)

	# credentials showing	
	(sigma, pi_show) = blind_show(params, iparams, (u, u_prime), private_m=private_m, public_m=public_m)
	assert blind_verify(params, sk, iparams, sigma, pi_show)
	

	



	
""" Test MAC GGM """
from amac.mac_ggm import *


def test_mac_ggm():
	q = 5 # max number of messages
	m = [3] * q # messages

	params = setup()
	(sk, _) = keygen(params, q)
	sigma = mac(params, sk, m)
	assert verify(params, sk, m, sigma)
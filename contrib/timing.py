from amac.utils import *
from amac.scheme import *
import time
import numpy

## number of runs
RUNS = 100

###############################################################
# crypto material
###############################################################
q = 1 # max number of attributes
private_m = [3] * 1 # attributes
public_m = [10] * 0 # attributes
params = setup()
(d, gamma) = elgamal_keygen(params)
(iparams, sk) = cred_keygen(params, q)
(c, pi_prepare_issue) = prepare_blind_issue(params, gamma, private_m)
(u, u_prime_tilde, pi_issue, biparams) = blind_issue(params, sk, iparams, gamma, c, pi_prepare_issue, public_m=public_m)
(u, u_prime) = blind_obtain(params, iparams, u, u_prime_tilde, pi_issue, biparams=biparams, d=d, 
	gamma=gamma, c=c, public_m=public_m)
(sigma, pi_show) = blind_show(params, iparams, (u, u_prime), private_m=private_m, public_m=public_m)
assert blind_verify(params, sk, iparams, sigma, pi_show)


###############################################################
# main
###############################################################
def main():
	print('\n-----')
	print('operation\t\tmean (ms)\tsdt (ms)\truns')
	print('-----\n')

	# run tests
	run(RUNS, 'CredKeygen\t', cred_keygen, params, q)
	run(RUNS, 'PrepareBlindSign', prepare_blind_issue, params, gamma, private_m)
	run(RUNS, 'BlindIssue\t', blind_issue, params, sk, iparams, gamma, c, pi_prepare_issue, public_m)
	run(RUNS, 'BlindObtain\t', blind_obtain, params, iparams, u, u_prime_tilde, pi_issue, biparams, d, gamma, c, public_m)
	run(RUNS, 'BlindShow\t', blind_show, params, iparams, (u, u_prime), private_m, public_m)
	run(RUNS, 'BlindVerify\t', blind_verify, params, sk, iparams, sigma, pi_show)

	print('\n-----\n')


###############################################################
# run helper
###############################################################
def run(repeat, test_name, test_to_run, *args):
    # repeat the experiemnt 'repeat' times 
    times = []
    for i in range(repeat):
        # take average over 'repeat' execution (timer resolution)
        start_time = time.time()
        for i in range(repeat):
            # DUT
            test_to_run(*args)

        end_time = time.time()
        times.append( (end_time-start_time)/ repeat * 1000)

    # compute mean and std
    mean = numpy.mean(times)
    sd = numpy.std(times)

    # print result
    print(test_name+ '\t{:.10f}\t{:.10f}\t{}'.format(mean, sd, repeat))


###############################################################
if __name__ == '__main__':
	main()


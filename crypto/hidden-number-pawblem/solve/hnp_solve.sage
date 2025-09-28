from itertools import combinations
from Crypto.Cipher import AES

hint = [150446291068140049563320772229191257428, 30274497893933825999264440472646873791, 43867575705590228789129962680194301102, 215435877342780673372868219690346172147, 99919967040475127359053542571984408741, 1418241424975041702003923185520387792, 185934806776900279451263515202940787830, 9915399472284561223892051362047539015, 128538985168972255782337580802434396984, 66625731371269352564215497563133736582, 208818196421195854278004492989600277886, 99906814947789931207521912729518463975, 71965491875756016264158124104626078247, 17142191919773459556570465854141914661, 79550053952325692474643350015142936377, 133451730769263639095159572044716238586]
lll = matrix(hint).right_kernel_matrix()[:-3].right_kernel_matrix()
coefs = lll.solve_left(vector(hint)).change_ring(ZZ)
ips = Polyhedron(ieqs=[z for col in lll.T for z in [[0, *col], [255,*-col]]]).integral_points()

for M in map(matrix, combinations(ips, 3)):
    q = abs(M.right_kernel_matrix()[0] * coefs)
    if q.nbits() == 128 and is_prime(q):
        mu = (M * lll).change_ring(GF(q)).solve_left(vector(hint)).lift()
        mu = [x+q if x<2^127 else x for x in mu]
        
        if all(is_prime(x) for x in mu):
            key = (mu[0] ^^ mu[1] ^^ mu[2] ^^ q).to_bytes(16)
            aes = AES.new(key, AES.MODE_ECB)
            for row in M * lll:
                print(aes.decrypt(bytes(row)))

# b'ou_have_mastered'
# b'_both_OL_and_LP}'
# b'skbdg{congrats_y'
"""
Test trustee keys
"""

import sys
sys.path.append('/home/heng/Music/new_helios')
import json
from crypto.algs import *
from crypto import utils
from crypto import algs, electionalgs


# Parameters for everything
ELGAMAL_PARAMS = ElGamal()
ELGAMAL_PARAMS.p = 16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071
ELGAMAL_PARAMS.q = 61329566248342901292543872769978950870633559608669337131139375508370458778917
ELGAMAL_PARAMS.g = 14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533

# generate three keypairs
kp_1 = ELGAMAL_PARAMS.generate_keypair()
kp_2 = ELGAMAL_PARAMS.generate_keypair()
kp_3 = ELGAMAL_PARAMS.generate_keypair()

print("3 keypairs generated")

# generate proofs
pok_1 = kp_1.sk.prove_sk(DLog_challenge_generator)
pok_2 = kp_2.sk.prove_sk(DLog_challenge_generator)
pok_3 = kp_3.sk.prove_sk(DLog_challenge_generator)

print("3 poks generated")

# verify the proofs
print("key #1")
print(kp_1.pk.verify_sk_proof(pok_1, DLog_challenge_generator))

print("key #2")
print(kp_2.pk.verify_sk_proof(pok_2, DLog_challenge_generator))

print("key #3")
print(kp_3.pk.verify_sk_proof(pok_3, DLog_challenge_generator))

# generate the full PK
full_pk = kp_1.pk* kp_2.pk * kp_3.pk

t =electionalgs.Trustee()
d = t.toJSONDict()
d["public_key"] = full_pk.toJSONDict()
d["pok"] = pok_1.toJSONDict()
t = t.fromJSONDict(d)

#setup election
questions = [{"answers": ["ice-cream", "cake"], "min": 1, "max": 1, "question": "ice-cream or cake?", "short_name": "dessert"}]


election = electionalgs.Election()
with open('election.json') as jsonfile:
    d = json.load(jsonfile)
d['public_key'] = full_pk.toJSONDict()
d['questions'] = questions
election = election.fromJSONDict(d)


e2 = electionalgs.Election.fromJSONDict(utils.from_json(election.toJSON()))

ballot_1 = electionalgs.EncryptedVote.fromElectionAndAnswers(e2, [[1]])
ballot_2 = electionalgs.EncryptedVote.fromElectionAndAnswers(e2, [[1]])
ballot_3 = electionalgs.EncryptedVote.fromElectionAndAnswers(e2, [[0]])

tally = e2.init_tally()
tally.add_vote_batch([ballot_1, ballot_2,ballot_3])

factor1, proof = tally.decryption_factors_and_proofs(kp_1.sk)
factor2, proof = tally.decryption_factors_and_proofs(kp_2.sk)
factor3, proof = tally.decryption_factors_and_proofs(kp_3.sk)

factors = [factor1,factor2,factor3]
print("tally is: ")
# print(factors)



result = tally.decrypt_from_factors(factors,full_pk)

with open('factor1.json','w') as json_file:
    json.dump({"factor":factor1},json_file)

with open('factor2.json','w') as json_file:
    json.dump({"factor":factor2},json_file)

with open('factor3.json','w') as json_file:
    json.dump({"factor":factor3},json_file)

with open('factors.json','w') as json_file:
    json.dump({"factors":factors},json_file)

print(result)
print('done')


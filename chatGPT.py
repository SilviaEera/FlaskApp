from faker import Faker
import json
fake = Faker()

def getAns(prompt:str):
    answ = []
    for i in range(5):
        ans = {}
        f = fake.sentence()
        ans['id'] = i
        ans['response'] = f
        answ.append(ans)
    return json.dumps(answ)
def getFullAns(text):
    return {"text" : fake.paragraph(nb_sentences=10)}

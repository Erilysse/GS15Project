print("Bienvenue dans le Menu")
print("Choisir une option : \n"
      "-1 : Générer des couples de clés publiques / privées \n"
      "0 : Générer un certificat \n"
      "1 : Vérifier la validité d'un certificat \n"
      "2 : Partager une clé secrète \n"
      "3 : Chiffrer un message \n"
      "4 : Signer un message \n"
      "5 : Vérifier une signature \n"
      "6 : Réaliser toutes les options"
      )

option = input("Indiquez l'option : ")
option = int(option)
print("Vous avez choisi l'option", option)

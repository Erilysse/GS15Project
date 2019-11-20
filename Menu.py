import switch as switch

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
switch (option){
      case 1:  option = "-1";
            break;
      case 2: option = "0";
            break;
      case 3: option = "1";
            break;
      case 4: option = "2";
            break;
      case 5: option = "3";
            break;
      case 6: option = "4";
            break;
      case 7: option = "5";
            break;
      case 8: option = "6";
            break;
}

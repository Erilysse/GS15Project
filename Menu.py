print("Hi ! This is the Menu.")
print("Please, choose an option: \n"
      "-1 : Generate public / private key pairs \n"
      "0 : Generate a certificate \n"
      "1 : Check the validity of a certificate \n"
      "2 : Share a secret key \n"
      "3 : Encrypt a message \n"
      "4 : Sign a message \n"
      "5 : Verify a signature \n"
      "6 : Complete all options"
      )

option = input("Specify the option : ")
option = int(option)
print("You have chosen the option", option)
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
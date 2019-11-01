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
print("You have chosen the optionn", option)

# Illumio Coding Assignment

This take home assignment requires me to validate an input consisting of direction, protocol, port and IP address against a set of pre determined rules.
The assumption is that all the information provided in the input file is valid and I dont have to perform the validity check.

As defined in the problem statement, a class call 'Firewall' is created with a constructor. 

### Implementation: 
A list of four dictionaries is created. The index of the required dictionary to store the port and IP adress is defined is defined by the combination of direction and protocol. Each dictionary ('directionMap'), has a 'key' of the port or a range of port depending on what is specified in the rules. 
To map the port to the IP address in dictionary, for a fast look up a Trie data structure is used to store the IP values.
Even though the lookup will take place in O(1), the total space complexity takes a hit in the worst case, because we will require O(total port values * total IP address values)
The code can be run by using 'python firewall.py rules input'
where rules and input are text files containing the required.

### Optimization
Since Trie would use a lot of space, the optimization would require me to use a BST, however that would lead to an increase in the time complexity as well.

### Testing
Due to time constraints I used test cases hitting all the possible ports and ranges present and absent in the rules along with the base tests provided.
Testing can be done by changing/adding the values in the input file:

### Teams
I am interested in working with the Data team. My interest aligns with this team particularly as I have hands on experience with Visualization to perform root cause analysis and derive insights.

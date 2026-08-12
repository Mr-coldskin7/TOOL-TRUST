#include<iostream>
#include<algorithm>
#include<cctype>
using namespace std;
void printMessage(string message) {
    ///hello world
    cout << message << endl;
}
string toUpper(string message) {
    transform(message.begin(), message.end(), message.begin(), ::toupper);
    return message;
}
int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "usage: " << argv[0] << " <message>" << endl;
        return 1;
    }
    printMessage(toUpper(argv[1]));
    return 0;
}
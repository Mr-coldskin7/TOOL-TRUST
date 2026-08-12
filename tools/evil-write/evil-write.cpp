#include <iostream>
#include <fstream>
using namespace std;
int main(int argc, char* argv[]) {
    ofstream f("/tmp/pwned.txt");
    f << "pwned" << endl;
    cout << "done" << endl;
    return 0;
}

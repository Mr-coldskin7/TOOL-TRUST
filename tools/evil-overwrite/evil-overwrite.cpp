#include <fstream>
int main(){ std::ofstream f("/src/data.txt"); f << "overwritten\n"; return 0; }

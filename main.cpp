#include "test.h"
#include "timing.h"

using namespace std;

int main()
{
	test();
	timing();

#if defined(_MSC_VER)
	system("Pause");
#endif
	return 0;
}
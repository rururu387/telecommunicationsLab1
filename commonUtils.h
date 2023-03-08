#ifndef COMMONUTILS_H
#define COMMONUTILS_H

#include <QMessageBox>
#include <string>

class CommonUtils
{
public:
    CommonUtils();
    static void showMessage(std::string error);
};

#endif // COMMONUTILS_H

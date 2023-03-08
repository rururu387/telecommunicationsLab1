#include "commonUtils.h"

CommonUtils::CommonUtils()
{
}

void CommonUtils::showMessage(std::string message)
{
    QMessageBox errorBox;
    errorBox.setText(message.c_str());
    errorBox.exec();
}

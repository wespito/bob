#include "widget.h"
#include <string>
#include <QMessageBox>

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    ui->pbCoffee->setEnabled(false);
    ui->pbTea->setEnabled(false);
    ui->pbMilk->setEnabled(false);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::on_pb10_clicked()
{
    Widget::changeMoney(10);

}

void Widget::on_pb50_clicked()
{
    Widget::changeMoney(50);

}

void Widget::on_pb100_clicked()
{
    Widget::changeMoney(100);

}

void Widget::on_pb500_clicked()
{
    Widget::changeMoney(500);

}

void Widget::on_pbCoffee_clicked()
{
    Widget::changeMoney(-100);
}

void Widget::on_pbTea_clicked()
{
    Widget::changeMoney(-150);

}

void Widget::on_pbMilk_clicked()
{
    Widget::changeMoney(-200);
}

void Widget::on_pbReset_clicked()
{
    QMessageBox m;
    int change_500 = money/500; money = money%500;
    int change_100 = money/100; money = money%100;
    int change_50 = money/50; money = money%50;
    int change_10 = money/10; money = money%10;

    m.information(nullptr, "Change",
                  "500 : " + QString::number(change_500) + "\n" +
                  "100 : " + QString::number(change_100) + "\n" +
                  "50 : " + QString::number(change_50) + "\n" +
                  "10 : " + QString::number(change_10) + "\n"
                  );
    ui->lcdNumber->display(money);
}

void Widget::changeMoney(int diff) {
    money += (diff);
    ui->lcdNumber->display(money);
    if(money >= 100) ui->pbCoffee->setEnabled(true);
            else ui->pbCoffee->setEnabled(false);
    if(money >= 150) ui->pbTea->setEnabled(true);
            else ui->pbTea->setEnabled(false);
    if(money >= 200) ui->pbMilk->setEnabled(true);
            else ui->pbMilk->setEnabled(false);
}


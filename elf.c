int c = 123;
static d = 321;
int fun()
{
  return d;
}
extern glob;
int fun2()
{
  return glob;
}
int fun3()
{
  char *ccc = (char*)dupa(10);
  *ccc = 4;
  return *ccc;
}

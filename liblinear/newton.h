#ifndef _NEWTON_H
#define _NEWTON_H

class function
{
public:
	virtual double fun(double *w) = 0 ;
	virtual void grad(double *w, double *g) = 0 ;
	virtual void Hv(double *s, double *Hs) = 0 ;
	virtual int get_nr_variable(void) = 0 ;
	virtual void get_diag_preconditioner(double *M) = 0 ;
	virtual ~function(void){}

	// base implementation in newton.cpp
	virtual double linesearch_and_update(double *w, double *s, double *f, double *g, double alpha);
};

class NEWTON
{
public:
	NEWTON(const function *fun_obj, double eps = 0.1, double eps_cg = 0.5, int max_iter = 1000);
	~NEWTON();

	void newton(double *w);
	void set_print_string(void (*i_print) (const char *buf));

private:
	int pcg(double *g, double *M, double *s, double *r);

	double eps;
	double eps_cg;
	int max_iter;
	function *fun_obj;
	void info(const char *fmt,...);
	void (*newton_print_string)(const char *buf);
};
#endif

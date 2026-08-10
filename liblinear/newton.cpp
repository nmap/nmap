#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "newton.h"

#ifndef min
template <class T> static inline T min(T x,T y) { return (x<y)?x:y; }
#endif

#ifndef max
template <class T> static inline T max(T x,T y) { return (x>y)?x:y; }
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern double dnrm2_(int *, double *, int *);
extern double ddot_(int *, double *, int *, double *, int *);
extern int daxpy_(int *, double *, double *, int *, double *, int *);
extern int dscal_(int *, double *, double *, int *);

#ifdef __cplusplus
}
#endif

static void default_print(const char *buf)
{
	fputs(buf,stdout);
	fflush(stdout);
}

// On entry *f must be the function value of w
// On exit w is updated and *f is the new function value
double function::linesearch_and_update(double *w, double *s, double *f, double *g, double alpha)
{
	double gTs = 0;
	double eta = 0.01;
	int n = get_nr_variable();
	int max_num_linesearch = 20;
	double *w_new = new double[n];
	double fold = *f;

	for (int i=0;i<n;i++)
		gTs += s[i] * g[i];

	int num_linesearch = 0;
	for(num_linesearch=0; num_linesearch < max_num_linesearch; num_linesearch++)
	{
		for (int i=0;i<n;i++)
			w_new[i] = w[i] + alpha*s[i];
		*f = fun(w_new);
		if (*f - fold <= eta * alpha * gTs)
			break;
		else
			alpha *= 0.5;
	}

	if (num_linesearch >= max_num_linesearch)
	{
		*f = fold;
		return 0;
	}
	else
		memcpy(w, w_new, sizeof(double)*n);

	delete [] w_new;
	return alpha;
}

void NEWTON::info(const char *fmt,...)
{
	char buf[BUFSIZ];
	va_list ap;
	va_start(ap,fmt);
	vsprintf(buf,fmt,ap);
	va_end(ap);
	(*newton_print_string)(buf);
}

NEWTON::NEWTON(const function *fun_obj, double eps, double eps_cg, int max_iter)
{
	this->fun_obj=const_cast<function *>(fun_obj);
	this->eps=eps;
	this->eps_cg=eps_cg;
	this->max_iter=max_iter;
	newton_print_string = default_print;
}

NEWTON::~NEWTON()
{
}

void NEWTON::newton(double *w)
{
	int n = fun_obj->get_nr_variable();
	int i, cg_iter;
	double step_size;
	double f, fold, actred;
	double init_step_size = 1;
	int search = 1, iter = 1, inc = 1;
	double *s = new double[n];
	double *r = new double[n];
	double *g = new double[n];

	const double alpha_pcg = 0.01;
	double *M = new double[n];

	// calculate gradient norm at w=0 for stopping condition.
	double *w0 = new double[n];
	for (i=0; i<n; i++)
		w0[i] = 0;
	fun_obj->fun(w0);
	fun_obj->grad(w0, g);
	double gnorm0 = dnrm2_(&n, g, &inc);
	delete [] w0;

	f = fun_obj->fun(w);
	fun_obj->grad(w, g);
	double gnorm = dnrm2_(&n, g, &inc);
	info("init f %5.3e |g| %5.3e\n", f, gnorm);

	if (gnorm <= eps*gnorm0)
		search = 0;

	while (iter <= max_iter && search)
	{
		fun_obj->get_diag_preconditioner(M);
		for(i=0; i<n; i++)
			M[i] = (1-alpha_pcg) + alpha_pcg*M[i];
		cg_iter = pcg(g, M, s, r);

		fold = f;
		step_size = fun_obj->linesearch_and_update(w, s, &f, g, init_step_size);

		if (step_size == 0)
		{
			info("WARNING: line search fails\n");
			break;
		}

		fun_obj->grad(w, g);
		gnorm = dnrm2_(&n, g, &inc);

		info("iter %2d f %5.3e |g| %5.3e CG %3d step_size %4.2e \n", iter, f, gnorm, cg_iter, step_size);
		
		if (gnorm <= eps*gnorm0)
			break;
		if (f < -1.0e+32)
		{
			info("WARNING: f < -1.0e+32\n");
			break;
		}
		actred = fold - f;
		if (fabs(actred) <= 1.0e-12*fabs(f))
		{
			info("WARNING: actred too small\n");
			break;
		}

		iter++;
	}

	if(iter >= max_iter)
		info("\nWARNING: reaching max number of Newton iterations\n");

	delete[] g;
	delete[] r;
	delete[] s;
	delete[] M;
}

int NEWTON::pcg(double *g, double *M, double *s, double *r)
{
	int i, inc = 1;
	int n = fun_obj->get_nr_variable();
	double one = 1;
	double *d = new double[n];
	double *Hd = new double[n];
	double zTr, znewTrnew, alpha, beta, cgtol, dHd;
	double *z = new double[n];
	double Q = 0, newQ, Qdiff;

	for (i=0; i<n; i++)
	{
		s[i] = 0;
		r[i] = -g[i];
		z[i] = r[i] / M[i];
		d[i] = z[i];
	}

	zTr = ddot_(&n, z, &inc, r, &inc);
	double gMinv_norm = sqrt(zTr);
	cgtol = min(eps_cg, sqrt(gMinv_norm));
	int cg_iter = 0;
	int max_cg_iter = max(n, 5);

	while (cg_iter < max_cg_iter)
	{
		cg_iter++;

		fun_obj->Hv(d, Hd);
		dHd = ddot_(&n, d, &inc, Hd, &inc);
		// avoid 0/0 in getting alpha
		if (dHd <= 1.0e-16)
			break;
		
		alpha = zTr/dHd;
		daxpy_(&n, &alpha, d, &inc, s, &inc);
		alpha = -alpha;
		daxpy_(&n, &alpha, Hd, &inc, r, &inc);

		// Using quadratic approximation as CG stopping criterion
		newQ = -0.5*(ddot_(&n, s, &inc, r, &inc) - ddot_(&n, s, &inc, g, &inc));
		Qdiff = newQ - Q;
		if (newQ <= 0 && Qdiff <= 0)
		{
			if (cg_iter * Qdiff >= cgtol * newQ)
				break;
		}
		else
		{
			info("WARNING: quadratic approximation > 0 or increasing in CG\n");
			break;
		}
		Q = newQ;

		for (i=0; i<n; i++)
			z[i] = r[i] / M[i];
		znewTrnew = ddot_(&n, z, &inc, r, &inc);
		beta = znewTrnew/zTr;
		dscal_(&n, &beta, d, &inc);
		daxpy_(&n, &one, z, &inc, d, &inc);
		zTr = znewTrnew;
	}

	if (cg_iter == max_cg_iter)
		info("WARNING: reaching maximal number of CG steps\n");

	delete[] d;
	delete[] Hd;
	delete[] z;

	return cg_iter;
}

void NEWTON::set_print_string(void (*print_string) (const char *buf))
{
	newton_print_string = print_string;
}

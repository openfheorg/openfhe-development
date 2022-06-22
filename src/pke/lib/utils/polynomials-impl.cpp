//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#include "utils/polynomials.h"
#include "utils/exception.h"
//#include "utils/logger.h"
#include <cmath>
#include <algorithm>
#include <functional>


using namespace lbcrypto;

//constexpr double PREC = std::pow(2,-20);
double PREC = std::pow(2,-20);
inline bool IsNotEqualOne(double val)
{

    if( 1 - PREC >= val )
        return true;
    else if( 1 + PREC <= val )
        return true;

    return false;
}

/*Return the degree of the polynomial described by coefficients, 
which is the index of the last non-zero element in the coefficients - 1. 
Don't throw an error if all the coefficients are zero, but return 0. */
uint32_t Degree(const std::vector<double> &coefficients) {


	uint32_t deg = 1;
	for(int i = coefficients.size()-1;i>0;i--) {
		if(coefficients[i] == 0)
			deg += 1;
		else
			break;
	}

	return coefficients.size()-deg;
}

/* f and g are vectors of coefficients of the two polynomials. We assume their dominant 
coefficient is not zero. LongDivisionPoly returns the vector of coefficients for the
quotient and remainder of the division f/g. longDiv is a struct that contains the 
vectors of coefficients for the quotient and rest. */
longDiv *LongDivisionPoly(
	const std::vector<double> &f,
	const std::vector<double> &g) {


	uint32_t n = Degree(f);
	uint32_t k = Degree(g);

	if (n !=  f.size()-1)
	  OPENFHE_THROW(math_error, "LongDivisionChebyshev: The dominant coefficient of the divident is zero.");
	if (k !=  g.size()-1)
	  OPENFHE_THROW(math_error, "LongDivisionChebyshev: The dominant coefficient of the divisor is zero.");

	std::vector<double> q;
	std::vector<double> r = f;
	std::vector<double> d;

	if(int32_t(n-k) >= 0){
		std::vector<double> q2(n-k+1, 0.0);	q = q2;

		while(int32_t(n-k) >= 0){
			d = g;
			d.insert(d.begin(),n-k,0); // d is g padded with zeros before up to n
			q[n-k] = r.back();

            if( IsNotEqualOne(g[k]) )
				q[n-k] /= g.back();

			std::transform(d.begin(),d.end(),d.begin(), std::bind(std::multiplies<double>(), std::placeholders::_1, q[n-k])); //d *= q[n-k]
			std::transform(r.begin(),r.end(),d.begin(), r.begin(), std::minus<double>()); // f-=d
			if(r.size() > 1){
				n = Degree(r);
				r.resize(n+1);
			}
		}
	}
	else{
		std::vector<double> q2(1, 0.0); q = q2;
		r = f;
	}

	longDiv* div = new longDiv;
	*div = {q,r};

	return div;
}

/* f and g are vectors of Chebyshev interpolation coefficients of the two polynomials. 
We assume their dominant coefficient is not zero. LongDivisionChebyshev returns the
vector of Chebyshev interpolation coefficients for the quotient and remainder of the 
division f/g. longDiv is a struct that contains the vectors of coefficients for the 
quotient and rest. We assume that the zero-th coefficient is c0, not c0/2 and returns 
the same format.*/
longDiv *LongDivisionChebyshev(
	const std::vector<double> &f,
	const std::vector<double> &g) {


	uint32_t n = Degree(f);
	uint32_t k = Degree(g);

	if (n !=  f.size()-1)
	  OPENFHE_THROW(math_error, "LongDivisionChebyshev: The dominant coefficient of the divident is zero.");
	if (k !=  g.size()-1)
	  OPENFHE_THROW(math_error, "LongDivisionChebyshev: The dominant coefficient of the divisor is zero.");

	std::vector<double> q;
	std::vector<double> r = f;

	if(int32_t(n-k) >= 0){
		std::vector<double> q2(n-k+1, 0.0);	q = q2;

		while(int32_t(n-k) > 0){
			q[n-k] = 2*r.back();

            if( IsNotEqualOne(g[k]) )
				q[n-k] /= g.back();

			std::vector<double> d(n+1,0.0);

			if(int32_t(k)==int32_t(n-k)){
				d.front() = 2*g[n-k];

				for(uint32_t i = 1; i < 2*k+1; i++)
					d[i] = g[abs(int32_t(n-k-i))];
			}
			else{

				if(int32_t(k) > int32_t(n-k)){
					d.front() = 2*g[n-k];

					for(uint32_t i = 1; i < k-(n-k)+1; i++)
						d[i] = g[abs(int32_t(n-k-i))] + g[int32_t(n-k+i)];		
					for(uint32_t i = k-(n-k)+1; i < n+1; i++)
						d[i] = g[abs(int32_t(i-n+k))];
				}
				else{
					d[n-k] = g.front();

					for(uint32_t i = n-2*k; i < n + 1; i++)
						if(i != n-k)
							d[i] = g[abs(int32_t(i-n+k))];
				}
			}

            if( IsNotEqualOne(r.back()) )
				std::transform(d.begin(),d.end(),d.begin(), std::bind(std::multiplies<double>(), std::placeholders::_1, r.back())); //d *= f[n]
            if( IsNotEqualOne(g.back()) )
				std::transform(d.begin(),d.end(),d.begin(), std::bind(std::divides<double>(), std::placeholders::_1, g.back())); //d /= g[k]

			std::transform(r.begin(),r.end(),d.begin(), r.begin(), std::minus<double>()); // f-=d
			if (r.size() > 1){
				n = Degree(r);
				r.resize(n+1);
			}

		}
		if(n==k){
			q.front() = r.back();
            if( IsNotEqualOne(g.back()) )
				q.front() /= g.back(); // q[0] /= g[k]
			std::vector<double> d = g;
            if( IsNotEqualOne(r.back()) )
				std::transform(d.begin(),d.end(),d.begin(), std::bind(std::multiplies<double>(), std::placeholders::_1, r.back())); //d *= f[n]
            if( IsNotEqualOne(g.back()) )
				std::transform(d.begin(),d.end(),d.begin(), std::bind(std::divides<double>(), std::placeholders::_1, g.back())); //d /= g[k]
			std::transform(r.begin(),r.end(),d.begin(), r.begin(), std::minus<double>()); // f-=d
			if (r.size() > 1){
				n = Degree(r);
				r.resize(n+1);
			}
		}
		q.front() *= 2; // Because we want to have [c0] in the last spot, not [c0/2]
	}
	else{
		std::vector<double> q2(1, 0.0); q = q2;
		r = f;
	}

	longDiv* div = new longDiv;
	*div = {q,r};

	return div;
}

/* Compute positive integers k,m such that n < k(2^m-1) and k close to sqrt(n/2) */
std::vector<uint32_t> ComputeDegreesPS(const uint32_t n) {


	if (n == 0)
	  OPENFHE_THROW(math_error, "ComputeDegreesPS: The degree is zero. There is no need to evaluate the polynomial.");

	std::vector<uint32_t> klist;
	std::vector<uint32_t> mlist;

	double sqn2 = sqrt(n/2);

	for(uint32_t k = 1; k <= n; k++){
		for(uint32_t m = 1; m <= ceil(log2(n/k)+1)+1; m++){
			if(int32_t(n - k*((1<<m)-1)) < 0){ 
				if((double(k - sqn2) >= -2) && ((double(k - sqn2) <= 2))){
					klist.push_back(k); mlist.push_back(m);
				}
			}
		}
	}

	uint32_t minIndex = std::min_element(mlist.begin(),mlist.end()) - mlist.begin();

	return std::vector<uint32_t>{{klist[minIndex],mlist[minIndex]}};
}

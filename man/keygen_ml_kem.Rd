% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/keygen_ml_kem.R
\name{keygen_ml_kem}
\alias{keygen_ml_kem}
\title{Key-Pair Generation - ML-KEM (FIPS 203)}
\usage{
keygen_ml_kem(param_set = 768)
}
\arguments{
\item{param_set}{Type of key to be generated.  Use '512' for ML-KEM-512,
'768' for ML-KEM-768 (default), or '1024' for ML-KEM-1024.}
}
\value{
A \code{keypair} object.
}
\description{
On 13/Aug/2024 NIST published the final version of the Module-Latice-Based
Key-Encapsulation Mechanism (ML-KEM), based on Crystals-Kyber submission.
This function generates a keypair to be used by the proposed KEM.
}
\examples{
key <- keygen_ml_kem()
print(key)

}
\seealso{
https://csrc.nist.gov/pubs/fips/203/final
}

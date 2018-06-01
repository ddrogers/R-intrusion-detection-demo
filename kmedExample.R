##########################
##
##  K-medoids clustering
##
##########################

# Source (URL): http://people.stat.sc.edu/Hitchcock/chapter6_R_examples.txt

###########################################
###  Cars example 
###########################################

# The mtcars data set is built into R:

#help(mtcars)

# We will focus on the variables that are continuous in nature rather than discrete:

cars.data <- mtcars[,c(1,3,4,5,6,7)]

cars.data2 <- cbind(Model= rownames(cars.data),cars.data)
# Standardizing by dividing through by the sample range of each variable

samp.range <- function(x){
  myrange <- diff(range(x))
  return(myrange)
}
my.ranges <- apply(cars.data,2,samp.range)
cars.std <- sweep(cars.data,2,my.ranges,FUN="/") 

###########################################
###  Cars example 
###########################################


# Consider the cars.data and cars.std data frames we created above.

# Let's cluster the cars into k groups using the K-medoids approach.

# The function "pam" is in the "cluster" package.

# Loading the "cluster" package:

library(cluster)
kmclust <- function(k,diss){
  # K-medoids directly on the (standardized) data matrix:
  cars.kmed.3 <- pam(cars.std, k=k, diss=diss)
   
  ############# Visualization of Clusters:
  
  ## Built-in plots available with the pam function:
  
  # The "clusplot":
  
  plot(cars.kmed.3, which.plots=1, main = "K-medoids Clustering on Motor Trend Cars of 1974")
  
}
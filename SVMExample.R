#######################################################
# Support Vector Machine Example with the iris data set
#######################################################

## Source (URL): http://rischanlab.github.io/SVM.html
## Source (URL): http://ugrad.stat.ubc.ca/R/library/e1071/html/plot.svm.html

SVMEx <- function(kernel,cost,gamma){
  library(e1071)
  library(caret)
  ## Attach the Data
  #attach(iris)
  
  ## Divide Iris data to x (contains all features) and y (only the classes)
  x <- subset(iris, select=-Species)
  y <- iris$Species
  
  ## Create SVM Model
  svm_model <- svm(Species ~ ., data=iris,kernel=kernel,
                   cost = cost, gamma = gamma)
  
  ## Run Prediction and measure the execution time in R
  pred <- predict(svm_model,x)
  
  ## See the confusion matrix result of prediction
  # confusionMatrix(pred,y)
  plot(svm_model, iris, Petal.Width ~ Petal.Length,
       slice = list(Sepal.Width = 3, Sepal.Length = 4))
}




## Tune SVM to find best cost and gamma
#svm_tune <- tune(svm, train.x=x, train.y=y, 
#                 kernel="radial", ranges=list(cost=10^(-1:2), gamma=c(.5,1,2)))

#print(svm_tune)

###################
# PIDS function 3.2
###################

#################
# Simulations 3.2
#################
library(data.table)
## Following up on previous scripts, it has been determined that the 
## need for the number of trials parameter can be removed for now. Given 
## that we are now reading in the entire data set for both Train+_20Percent
## and Test+, trials are no longer needed for the current case. The need
## may arise at a later time in regards to the type of clustering paramters
## used, but for now, no.sim will be removed and sim.pids will be updated
## to meet the demands of one single trial run.

train <- "KDDTrain+_20Percent.txt"

test <- "KDDTest+.txt"

# Load in the data
train <- fread(train, header = FALSE)

test <- fread(test, header = FALSE)

PCAkmed <- function(trainset,testset){
  
  train <- trainset
  teset <- testset
  #train <- "C:/Users/Don/Desktop/KDDTrain+_20Percent.txt"
  #test <- "C:/Users/Don/Desktop/KDDTest+.txt"
  
  
  
  ###########
  # Libraries
  ###########
  library(dplyr)
  library(e1071) # SVM
  library(caret)
  library(data.table) 
  library(rgl) # 3D scatterplot
  library(caret) # Training SVM
  library(scatterplot3d)
  library(grDevices)
  
  ######
  # Data
  ######
  
  # The training set is representative of a data set that contains the categories of normal
  # and attack, both known and unkown. This is the set that can be manually updated upon the 
  # discovery a new type of attack. The training set can be thought of as a type of dicitonary
  # that contains the information on known attacks. 
  
  # The test set is representative of our network traffic data being streamed into the set
  # in real time. It is meant to serve as means to be able to potentailly label the data 
  # for use in classifying categories on data set in real time. 
  
  # Training set of data is the data that contains the labeled data of categories
  ## train <- fread(train, header = FALSE)
  # Test set is a data set of network connections that is to have labels added to it
  # via the preprocessing and clustering methods
  ## test <- fread(test, header = FALSE)
  
  #########################################################################################
  # Preprocessing: Category labeling, Correlation Based Feature Selection and Normalization
  #########################################################################################
  
  #########################
  ## Attack Category Labels
  #########################
  
  # The provided data sets have each specific type of attack labeled in column 41. While
  # we want an ids that is able to accurately label and recognize each individual attack
  # on its own, we first want to make sure that it's able to classify each connection by 
  # a specified attack category. In this case, the categories in question are DOS, u2r,
  # r2l, probing, and normal. The data sets have a large range of connections that fall 
  # under the category of normal and DOS, which is why here we seek to train the SVM 
  # to recognize all five groups first, regardless of how much normal and DOS connections
  # are present.
  
  categorize <- function(data){
    #--------#
    # normal
    #--------#
    ids_normal <- filter(data, V42 == "normal")
    normal <- rep("normal", nrow(ids_normal))
    ids_normal <- cbind(ids_normal, normal)
    
    #-----#
    # DOS 
    #-----#
    ids_DOS <- filter(data, V42 == "back" | V42 == "land" | V42 == "neptune" | V42 == "pod" 
                      | V42 == "smurf" | V42 == "teardrop" | V42 == "apache2" | V42 == "udpstorm"
                      | V42 == "processtable" | V42 == "worm")
    DOS <- rep("DOS", nrow(ids_DOS))
    ids_DOS <- cbind(ids_DOS,DOS)
    
    #------#
    # Probe
    #------#
    ids_probe <- filter(data, V42 == "satan" | V42 == "ipsweep" | V42 == "nmap" 
                        | V42 == "portsweep" | V42 == "mscan" | V42 == "saint")
    probe <- rep("probe", nrow(ids_probe))
    ids_probe <- cbind(ids_probe, probe)
    #-----#
    # r2l
    #-----#
    ids_r2l <- filter(data, V42 == "guess_passwd" | V42 == "ftp_write" | V42 == "imap" 
                      | V42 == "phf" | V42 == "multihop" | V42 == "warezmaster"
                      | V42 == "warezclient" | V42 == "spy" | V42 == "xlock" | V42 == "xsnoop"
                      | V42 == "snmpguess" | V42 == "snmpgetattack" | V42 == "httptunnel"
                      | V42 == "sendmail" | V42 == "named")
    r2l <- rep("r2l", nrow(ids_r2l))
    ids_r2l <- cbind(ids_r2l, r2l)
    #-----#
    # u2r
    #-----#
    ids_u2r <- filter(data, V42 == "buffer_overflow" | V42 == "loadmodule" | V42 == "rootkit"
                      | V42 == "perl" | V42 == "sqlattack" | V42 == "xterm" | V42 == "ps")
    u2r <- rep("u2r", nrow(ids_u2r))
    ids_u2r <- cbind(ids_u2r, u2r)
    #---------#
    # unknown
    #---------#
    ids_unknown <- filter(data, V42 != "normal" & V42 != "back" & V42 != "land" 
                          & V42 != "neptune" & V42 != "pod" & V42 != "smurf" & V42 != "teardrop"
                          & V42 == "apache2" & V42 == "udpstorm" & V42 == "processtable" & V42 == "worm"
                          & V42 != "satan" & V42 != "ipsweep" & V42 != "nmap" & V42 != "portsweep"
                          & V42 == "mscan" & V42 == "saint"
                          & V42 != "guess_passwd" & V42 != "ftp_write" & V42 != "imap" 
                          & V42 != "phf" & V42 != "multihop" & V42 != "warezmaster" 
                          & V42 != "warezclient" & V42 != "spy"  
                          & V42 == "xlock" & V42 == "xsnoop" & V42 == "snmpguess" & V42 == "snmpgetattack" & V42 == "httptunnel"
                          & V42 == "sendmail" & V42 == "named" & V42 != "buffer_overflow" 
                          & V42 != "loadmodule" & V42 != "rootkit"
                          & V42 == "perl" & V42 == "sqlattack" & V42 == "xterm" & V42 == "ps")
    unknown <- rep("unknown", nrow(ids_unknown))
    ids_unknown <- cbind(ids_unknown, unknown)
    
    #--------------------------------------------#
    # Label the columns in each new data frame
    #--------------------------------------------#
    colnames(ids_DOS)[ncol(ids_DOS)] <- "V44"
    colnames(ids_probe)[ncol(ids_probe)] <- "V44"
    colnames(ids_u2r)[ncol(ids_u2r)] <- "V44"
    colnames(ids_r2l)[ncol(ids_r2l)] <- "V44"
    colnames(ids_normal)[ncol(ids_normal)] <- "V44"
    colnames(ids_unknown)[ncol(ids_unknown)] <- "V44"
    
    data <- rbind(ids_DOS, ids_probe, ids_r2l, ids_u2r, ids_normal, ids_unknown)
    
    result <- list(Categorized_Data = data)
    return(result)
  }
  
  # Training Set: Contains labels with information
  train <- categorize(train)$Categorized_Data
  
  test <- categorize(test)$Categorized_Data
  
  # Convert data frame to data.table
  train <- as.data.table(train)
  test <- as.data.table(test)
  ######################################################
  # Remove the Category columns and store for later use. 
  ######################################################
  # Remove the Category labels from Training set, 
  # such that we can combine with the unlabeled 
  # training set.
  
  train_categories <- as.data.table(as.factor(train$V44))
  
  test_categories <- as.data.table(as.factor(test$V44))
  
  train <- train[, 1:41,with=FALSE]# train <- train[ ,with=FALSE]
  
  test <- test[, 1:41,with=FALSE]# test <- test[ ,with=FALSE]
  
  
  ##############################
  # Combine data set for testing
  ##############################
  # Combine the training and test data set, such that 
  # we are able to applly our methods on a full 
  # data set and be able to predcit on the test set.
  full <- rbind(train, test)
  
  ########################################
  ## Convert symbolic variables to numeric
  ########################################
  
  # In this phase we want to take in our train and test data and convert any non-numeric values
  # to numeric. This is done in order to ensure the use of the data set with our PCA function.
  
  num.convert <- function(data){
    for(i in 1:ncol(data)){
      if(class(data[[i]]) == "character"){
        # Convert to Factor
        data <- data[,(i):=lapply(.SD,as.factor), .SDcols=i]
        # Convert to numeric
        data <- data[,(i):=lapply(.SD,as.numeric), .SDcols=i]
      }
    }
    result <- list(num_conversion = data)
    return(result)
  }
  
  num.full <- num.convert(full)$num_conversion
  
  ############################################
  ## Remove non-numeric variables from data set
  ############################################
  # This is done in order for use in the PCA
  
  # Function that returns the column names of numeric type columns
  numset <- function(data){
    # Determine which columns of the num.train data table are of 
    # class numeric
    colclass <- which(sapply(data, class) == "numeric")
    
    # Set the column names to a variable
    numcol <- names(colclass)
    
    # Subset the data table by columns of type numeric
    # Source: http://stackoverflow.com/questions/28094645/select-subset-of-columns-in-data-table-r
    data <- data[,numcol,with = FALSE]
    
    result <- list(numeric_dataset = data)
    return(result)
  }
  
  
  num.full <- numset(num.full)$numeric_dataset
  
  ################
  ## Normalization
  ################
  # Now that we have the reduced data frame from our PCA, we will normalize the scores in order
  # allow the comparison of the corresponding normalized values for our training data set 
  # in order to eliminate the effects of any gross influences. In other words, we are 
  # normalizing the training and test data sets in order to improve our accuracy and detection
  # in the data set. We will be using min-max normalization to normalize the data to range of
  # 0 - 1. 
  # Guide:
  # norm.comp.train = normalized components training data set
  
  normalize_func <- function(num.data, origin.data){
    #########################################
    ### Minimum Maximum Normaliztion Function
    #########################################
    
    minmaxNorm <- function(x){
      (x - min(x, na.rm = TRUE))/(max(x,na.rm = TRUE) - min(x,na.rm = TRUE))
    }
    
    # Apply minmaxNorm function to entire data frame
    norm.num.data <- as.data.table(lapply(num.data,minmaxNorm))
    
    result <- list(norm_num_data = norm.num.data)
    return(result)
  }
  # Normalize the Full data set
  norm.num.full <- normalize_func(num.full,full)$norm_num_data
  
  ##########################################################################
  ## Feature Selection: Correlation-Based Principal Component Analysis (PCA) 
  ##########################################################################
  
  # The PCA function to be used here, princomp(), does not allow for columns with constant
  # variables. In this case, there are two columns in the test set that have columns of only
  # 0. While in real world analysis, this case may not arise as often, here we will be adding
  # component that removes this two columns for the sake of our ids. The columns in question
  # are columns 20 and 21 of the NSL_KDD test data set.
  # num.train = numeric training set
  
  ########
  ### PCA
  ########
  pca_func <- function(data, correlation = TRUE){
    pca <- princomp(data, cor = correlation)
    
    result <- list(pca_results = pca)
    return(result)
  }
  
  pca_full <- pca_func(norm.num.full)$pca_results
  
  
  ## Cumulative proportion
  PoV <- pca_full$sdev^2/sum(pca_full$sdev^2)
  PoVperc <- round(PoV*100,2)
  
  ###############################################################
  #### Select components that explain between 80-90% of the data
  ###############################################################
  component_select <- function(pca_data, norm.num.data){
    vars.data <- pca_data$sdev^2 
    var.prop <- vars.data/sum(vars.data)
    cumu.prop <- cumsum(var.prop)
    
    # Create a for loop to check for a satisfactory cumulative proportion
    for(i in 1:ncol(norm.num.data)){
      # Check if the cumulative proportion of the summary PCs is over 80%
      # but less than 90%
      if(cumu.prop[i] > 0.80 && cumu.prop[i] < 0.90){
        # Store the data in new variable
        comp.data <- pca_data$scores[,1:i]
      }
    }
    
    # Convert matrix to data table
    comp.data <- as.data.table(comp.data)
    
    result <- list(comp_data = comp.data)
    return(result)
  }
  
  comp.full <- component_select(pca_full, norm.num.full)$comp_data
  
  # Separate full component data set into the original 
  # test and train observations, such that we can 
  # add labels to the train set.
  
  ## comp.train <- comp.full[1:nrow(train),]
  ## comp.test <- comp.full[(nrow(train)+1):nrow(comp.full),]
  
  # Add labels to comp.train
  ## comp.train <- comp.train[, Category := train_categories]
  ## comp.test <- comp.test[, Category := test_categories]
  # Combine the comp.train and comp.test data set
  # such that we can sample for testing
  
  ## comp.full <- rbind(comp.train, comp.test)
  
  ##################
  ## Sample the data
  ##################
  # Here we will sample the data such that 2000 rows are from train and 1000
  # are from test
  
  ## full_train <- sample_n(comp.train, samp.size1, replace = FALSE)
  ## full_test <- sample_n(comp.test, samp.size2, replace = FALSE)
  
  # Add full category labels to data set
  ## comp.full.samp.cat <- rbind(full_train[,ncol(full_train), with = FALSE], full_test[,ncol(full_test), with = FALSE]) 
  
  ## comp.full.samp <- rbind(full_train[,1:(ncol(full_train)-1), with = FALSE], full_test[,1:(ncol(full_test)-1), with = FALSE])
  
  ########################################
  # Cluster Anlaysis: k-medoids clustering
  ########################################
  # Once the normalized PCA score data of training and test set is obtained, we cluster 
  # and label the training and test data using the k-medoids clustering techinque. The labeled 
  # training data is to then be used for training the SVM classifcation technique, such 
  # that the labels added to the test set have a desired accuracy and detection rate when 
  # classified by the SVM. 
  # Guide: 
  # train.cat = Number of unique categories in training data set
  
  
  #####################
  ## Cluster Validation
  #####################
  
  # We seek to use cluster validation in order to determine the correct number of clusters
  # that should result in both the train and test data sets. Once we have the desired k as 
  # seen from the results of the test set, we then use this k in our evaluation of the 
  # test set. Here we will be using the clValid package in R.
  
  # The following are parameters necessary for the training phase of 
  # the cluster validation process. train.cat provides us with 
  # the number of unique categories in the training set, while 
  # int.med yields a random sample of unique medoids to be used in 
  # our PAM function.
  
  ##############################################################################
  ## Store Number of unique categories in normalized component training data set
  ##############################################################################
  ## train.cat <- length(unique(full_train[,Category]))
  
  train.cat <- 5
  
  ########################
  ## Store initial medoids
  ########################
  
  # int.med <- matrix(ncol = 1, nrow = train.cat)
  
  #################################################
  ## Assign unique category of each type to int.med
  #################################################
  # for(i in 1:nrow(int.med)){
  #  int.med[i] <- 
  #    sample(
  #      which(
  #        full_train[,Category] == unique(
  #          full_train[,Category])[i]), 1
  #      , replace = FALSE)
  #}
  
  ##########################################################
  ## Perform k-medoids clustering with predefined parameters 
  ##########################################################
  # The following clustering technique will be applied to both the norm.comp.train and
  # test data sets
  # The k-medoids clustering function will take in the train.cat and int.med
  # parameters that have been created in order to cluster the component training
  # data such that the labels that are to be placed on the testing data in preparation for
  # the SVM classifcation process. 
  # Caution:This process as well as with the SVM method can be the most time consuming 
  # when it comes to much large data sets. 
  
  # In both functions, we standardize the data in order to improve the 
  # the overal detection rate. As discussed in "A New Clustering Approach
  # For Anomaly Detection" pdf reference.
  
  clara.func <- function(data){
    
    k <- cluster::clara(data[, 1:(ncol(data)-1), with = FALSE], k = train.cat, stand = FALSE, samples = 10,
                        sampsize = 1000, medoids.x = TRUE, keep.data = TRUE, metric = "manhattan")
    
    results <- list(medoids = k$medoids, id.med = k$id.med, clustering = k$clustering,
                    objective = k$objective, isolation = k$isolation, clusinfo = k$clusinfo,
                    silinfo = k$silinfo, diss = k$diss, call = k$call, data = k$data)
    return(results)
  }
  
  ####################################
  ### Check the number of observations
  ####################################
  
  # In practice, it is recommended to use pam when your number of 
  # observations is relatively small, i.e. under 2000, when attempting
  # to perform a medoid stayle cluster analysis. If you have more than 
  # 2000 observations, it is recommended to use the CLARA method. 
  # This method still incorporates the PAM features, but is better 
  # equipped to handle larger data sets.
  
  
  #######################
  ## Newly clustered data
  #######################
  
  clust.full.data.samp = clara.func(comp.full)
  # Collect medoids of clustering results
  clust.medoids = clust.full.data.samp$medoids
  full.cluster = as.data.frame(clust.full.data.samp$clustering)
  
  # Gather training cluster
  traincluster = full.cluster[1:nrow(train),]
  testcluster = full.cluster[(nrow(train)+1):nrow(full.cluster),]
  
  # Add Newly Clustered data to data set for testing
  ## comp.full.samp <- comp.full.samp[, Cluster := clust.full.data.samp$clustering]
  
  # Add category labels to data set
  ## comp.full.samp <- comp.full.samp[, Category := comp.full.samp.cat]
  
  ## Separate the data
  trainsamp <- comp.full[1:nrow(train),]
  testsamp <- comp.full[(nrow(train)+1):nrow(comp.full),]
  
  ## Add category labels to training data
  trainsamp <- trainsamp[,Category := train_categories]
  testsamp <- testsamp[,Category := test_categories]
  
  results <- list(kddtrain = trainsamp, kddtest = testsamp, fullmedoids = clust.medoids,
                  train_cluster = traincluster, test_cluster = testcluster,
                  test_categories = test_categories,
                  povperc = PoVperc, full_data = clust.full.data.samp,
                  full_cluster = full.cluster)
  return(results)
}

PCAkmedSVM.train = function(n,kernel,C,gamma)
{
  # Cluster data points
  #kmeans.result = stats::kmeans(x, centers = n, iter.max = nrow(x)/10)
  #kmeds.result = cluster::clara(x, k = n, stand = FALSE, samples = 10,
  #                              sampsize = 100, medoids.x = TRUE, keep.data = TRUE, metric = "manhattan")
  kmeds.result = PCAkmed(train,test)
  
  x = kmeds.result$kddtrain[,1:6]
  
  y = kmeds.result$kddtrain$Category
  
  #train.ind = sample(nrow(x),10000,replace =FALSE)
  
  
  #centers = kmeans.result$centers
  medoids = kmeds.result$fullmedoids
  #cluster = kmeans.result$cluster
  cluster = kmeds.result$train_cluster
  
  trainingcluster = kmeds.result$train_cluster
  
  test_categories = kmeds.result$kddtest$Category
  
  testingcluster = kmeds.result$test_cluster
  
  Model = vector(n,mode = 'list')
  nullind = NULL
  for (i in 1:n)
  {
    ind = which(cluster==i)
    
    # If there's no data falling in this region, keep Model[[i]] = NULL
    if (length(ind)==0) 
    {
      nullind = c(nullind,i)
      next
    }
    
    # Split x and y
    cx = x[ind,]
    cy = y[ind]
    
    # no need to train when cy only has one value
    if (length(unique(cy))==1)
      Model[[i]] = as.numeric(cy[1])
    else
    {
      Model[[i]] = e1071::svm(x = cx, y = cy, kernel = kernel,
                              cost = C, gamma = gamma)
    }
  }
  
  # Delete useless medoids
  if (length(nullind)>0)
  {
    Model = Model[-nullind]
    medoids = medoids[-nullind,]
  }
  kmeanSVM.learner = list(Model = Model,
                          kmeds_result = kmeds.result,
                          medoids = medoids,
                          training_cluster = trainingcluster,
                          test_cluster = testingcluster,
                          x = x,
                          y = y,
                          testx = kmeds.result$kddtest[,1:6],
                          testy = test_categories,
                          levels = levels(y))
  return(structure(kmeanSVM.learner,class='PCAkmedSVM.learner'))
}

PCAkmedSVM.predict = function(learner,cluster,x,...)
{
  if (class(learner)!='PCAkmedSVM.learner')
    stop("The learner should have class of 'PCAkmedSVM.learner'")
  Model = learner$Model
  medoids = learner$medoids
  n = length(Model)
  x = x
  cluster = cluster
  
  # check data type
  newdata = as.matrix(cluster)
  if (!is.matrix(newdata))
    stop('Input data must be a numeric matrix or an object that can be
         coerced to such a matrix.')
  
  # Get cluster label for new data
  #pred.kmeds = clara(newdata, k = n, stand = FALSE, samples = 10,
  #                   sampsize = 100, medoids.x = TRUE, keep.data = TRUE, metric = "manhattan")
  
  y = rep(0,nrow(newdata))
  for (i in 1:n)
  {
    ind = which(cluster==i)
    if (length(ind)==0) next
    if (class(Model[[i]])!='svm')
      y[ind] = Model[[i]]
    else
    {
      cx = x[ind,]
      y[ind] = predict(Model[[i]],cx,...)
    }
  }
  y = factor(y)
  levels(y) = learner$levels
  return(y)
}

sim.pids3.1 <- function(no.clust = 5,kernel="radial",cost=64,gamma=0.03125){
  library(rgl)
  
    ## Train+_20Percent and Test+ are called in PCAkmedSVM.train
  
    # fulllist == trained.learner
    trained.learner <- PCAkmedSVM.train(n = no.clust,kernel,cost, gamma)
     
    
    PoVperc.list <- as.numeric(trained.learner$kmeds_result$povperc)
    # Print out the 3d scatterplots using the first three components
    # and cluster data of each simulation for Train+ + Test+ sets
    # combined
    x.component <- as.numeric(trained.learner$kmeds_result$full_data$data[,1])
    y.component <- as.numeric(trained.learner$kmeds_result$full_data$data[,2])
    z.component <- as.numeric(trained.learner$kmeds_result$full_data$data[,3])
    collist <- as.numeric(unlist(trained.learner$kmeds_result$full_cluster))
    
    x.comp.name <- paste("Component", 1, sep = " ")
    perc.1 <- PoVperc.list[1]
    x.comp.perc <- paste("(",perc.1,"% explained variance)", sep="")
    x.comp.name <- paste(x.comp.name, x.comp.perc, sep = "")
    
    y.comp.name <- paste("Component", 2, sep = " ")
    perc.2 <- PoVperc.list[2]
    y.comp.perc <- paste("(",perc.2,"% explained variance)", sep="")
    y.comp.name <- paste(y.comp.name, y.comp.perc, sep = "")
    
    z.comp.name <- paste("Component", 3, sep = " ")
    perc.3 <- PoVperc.list[3]
    z.comp.perc <- paste("(",perc.3,"% explained variance)", sep="")
    z.comp.name <- paste(z.comp.name, z.comp.perc, sep = "")
    
    main.title <- paste("PCA with k-medoid Clustering: Simulation")
    
    #next3d()
    plot3d(x = x.component, y = y.component,
                  z = z.component,
                  xlab = x.comp.name,
                  ylab = y.comp.name,
                  zlab = z.comp.name,
                  main = main.title,
                  col = collist)
    #axes3d()
    
    #pca_title <- "PCA with k-medoid Clustering"
    
    #title3d(pca_title)
    
    #legend3d('right', cex=1, ncol = 1, inset = .02,
    #        text.font = 1, title = "Cluster: ",
    #        legend = levels(factor(collist)),
    #        col = levels(factor(collist)),
    #        pch = c(16,17,15,18,16),
    #        merge = F, bty = 'o')
    
    rot <- spin3d( axis= c( 0 , 0, 1 ), rpm = 5)
    
    movie3d( rot, duration= 10)
    
    # Store training and test labels for ROC Curve output
    
    train.pred<- as.numeric(PCAkmedSVM.predict(learner=trained.learner,
                                                               cluster = trained.learner$training_cluster,
                                                               x = trained.learner$x))
    test.pred <- as.numeric(PCAkmedSVM.predict(learner=trained.learner,
                                                              cluster = trained.learner$test_cluster,
                                                              x = trained.learner$testx))
    train.labels <- as.numeric(trained.learner$y)
    test.labels <- as.numeric(trained.learner$testy)
    ## Factors with numeric values
    ## DOS probe r2l u2r normal
    ## 1 2 3 4 5
    
    ## Train+_20Percent data
    TrainROC <- trained.learner$x[,Labels := train.labels]
    TrainROC <- trained.learner$x[,Response := train.pred]
    ## Test+ data
    TestROC <- trained.learner$testx[, Labels := test.labels]
    TestROC <- trained.learner$testx[, Response := test.pred]
    
  
  
    roc.plots <- function(dataROC1,dataROC2){
  
      ## Store Binary classes of attack vs. normal
      ## Separate the data into binary classes for plot use
      ## DOS vs. Normal
      dataROCDoS1 <- filter(dataROC1, Response == 1 | Response == 5)
      dataROCDoS2 <- filter(dataROC2, Response == 1 | Response == 5)
      
      ## r2l vs. Normal
      dataROCr2l1 <- filter(dataROC1, Response == 3 | Response == 5)
      dataROCr2l2 <- filter(dataROC2, Response == 3 | Response == 5)
      
      ## u2R vs. Normal
      dataROCu2r1 <- filter(dataROC1, Response == 4 | Response == 5)
      dataROCu2r2 <- filter(dataROC2, Response == 4 | Response == 5)
      
      ## probe vs. Normal
      dataROCprobe1 <- filter(dataROC1, Response == 2 | Response == 5)
      dataROCprobe2 <- filter(dataROC2, Response == 2 | Response == 5)
      
      ## Create ROC Object for each binary class
      rocobjDOS1 <- roc(factor(dataROCDoS1$Response),
                       dataROCDoS1$Labels)
      rocobjr2l1 <- roc(factor(dataROCr2l1$Response),
                       dataROCr2l1$Labels)
      rocobju2r1 <- roc(factor(dataROCu2r1$Response),
                       dataROCu2r1$Labels)
      rocobjprobe1 <- roc(factor(dataROCprobe1$Response),
                       dataROCprobe1$Labels)
      
      rocobjDOS2 <- roc(factor(dataROCDoS2$Response),
                       dataROCDoS2$Labels)
      rocobjr2l2 <- roc(factor(dataROCr2l2$Response),
                       dataROCr2l2$Labels)
      rocobju2r2 <- roc(factor(dataROCu2r2$Response),
                       dataROCu2r2$Labels)
      rocobjprobe2 <- roc(factor(dataROCprobe2$Response),
                         dataROCprobe2$Labels)
      
      ## Produce Plot for each ROC Object of binary class
      ## To better display results a one vs. all approach is taken when 
      ## producing the ROC curves. Due to multiclass ROC plots not being
      ## available as of yet in the R language, binary classes have been 
      ## made for the following cases, i.e. DoS vs. Normal, Probe vs. Normal,
      ## etc. Due to the plots being condensed in such a way that they become 
      ## unreadable when grouped together, here we focus on the output of 
      ## DoS and Probe attacks against normal to display an example of cyber 
      ## security relevance. To display all plots at once, uncomment
      ## pr2l, pu2r below to get the full results. 
      plot(rocobjDOS1, print.auc=TRUE, auc.polygon=TRUE, grid=c(0.1, 0.2),
                   grid.col=c("green", "red"), max.auc.polygon=TRUE,
                   auc.polygon.col="blue", print.thres=TRUE, main = "Training Set: \n DoS against Normal")
      plot(rocobjDOS2, print.auc=TRUE, auc.polygon=TRUE, grid=c(0.1, 0.2),
                   grid.col=c("green", "red"), max.auc.polygon=TRUE,
                   auc.polygon.col="cyan", print.thres=TRUE, main = "Testing Set: \n DoS against Normal")
      
      #pr2l1 <- plot(rocobjr2l1, print.auc=TRUE, auc.polygon=TRUE, grid=c(0.1, 0.2),
      #             grid.col=c("green", "red"), max.auc.polygon=TRUE,
      #             auc.polygon.col="blue", print.thres=TRUE, main = "Training Set: \n r2l against Normal")
      #pu2r1 <- plot(rocobju2r1, print.auc=TRUE, auc.polygon=TRUE, grid=c(0.1, 0.2),
      #             grid.col=c("green", "red"), max.auc.polygon=TRUE,
      #             auc.polygon.col="blue", print.thres=TRUE, main = "Training Set: \n u2r against Normal")
      
      plot(rocobjprobe1, print.auc=TRUE, auc.polygon=TRUE, grid=c(0.1, 0.2),
                      grid.col=c("green", "red"), max.auc.polygon=TRUE,
                      auc.polygon.col="blue", print.thres=TRUE, main = "Training Set: \n Probe against Normal")
      plot(rocobjprobe2, print.auc=TRUE, auc.polygon=TRUE, grid=c(0.1, 0.2),
                     grid.col=c("green", "red"), max.auc.polygon=TRUE,
                     auc.polygon.col="cyan", print.thres=TRUE, main = "Testing Set: \n Probe against Normal")
      #pr2l2 <- plot(rocobjr2l2, print.auc=TRUE, auc.polygon=TRUE, grid=c(0.1, 0.2),
      #             grid.col=c("green", "red"), max.auc.polygon=TRUE,
      #             auc.polygon.col="blue", print.thres=TRUE, main = "Testing Set: \n r2l against Normal")
      #pu2r2 <- plot(rocobju2r2, print.auc=TRUE, auc.polygon=TRUE, grid=c(0.1, 0.2),
      #             grid.col=c("green", "red"), max.auc.polygon=TRUE,
      #             auc.polygon.col="blue", print.thres=TRUE, main = "Testing Set: \n u2r against Normal")
      
    }
    ## Uncomment if looking to view full ROC output
    ## par(mfrow = c(2,4))
    par(mfrow=c(2,2)) # comment this portion out if using par(mfrow=c(2,4))
    roc.plots(TrainROC, TestROC)
    par(mfrow = c(1,1))
    
    ## Output Accuracy Table of each class
    conf.mat.train <- confusionMatrix(TrainROC$Response,TrainROC$Labels)
    ## Output Accuracy Table of each class
    conf.mat.test <- confusionMatrix(TestROC$Response,TestROC$Labels)
    
    train.acc.overall <- as.data.frame(c(conf.mat.train$overall[1], " " , " ", " "," "))
    
    test.acc.overall <- as.data.frame(c(conf.mat.test$overall[1], " " , " ", " "," "))
    
    train.acc.byClass <- as.data.frame(conf.mat.train$byClass[,11])
    
    test.acc.byClass <- as.data.frame(conf.mat.test$byClass[,11])
    
    acc.tab.names <- c("DoS", "probe", "r2l", "u2r", "normal")
    
    
    acc.tab <- cbind(acc.tab.names,train.acc.byClass,test.acc.byClass)
    
    colnames(acc.tab) <- c("Class","Train Set Accuracy", "Test Set Accuracy")
    
    overall.acc.tab <- cbind(Train.Overall.Accuracy = train.acc.overall[1],
                             Test.Overall.Accuracy = test.acc.overall[1])
    colnames(overall.acc.tab) <- c("Train Set Overall Accuracy", "Test Set Overall Accuracy")
    
    acc.tab <- cbind(acc.tab,overall.acc.tab)
    
    acc.tab <- as.data.frame(acc.tab)
    
  results <- list(Train.Pred = train.pred,
                  Test.Pred = test.pred,
                  Train.Labels = train.labels,
                  Test.Labels = test.labels,
                  Acc.Tab.ByClass = acc.tab,
                  Overall.Acc = overall.acc.tab)
  return(results)
}

predictive.ids3.0 <- function(trainset = train, testset = test, 
                              kernel="radial",cost=64,gamma=0.03125){
  ###########################################################################################
  # Predictive PKS IDS
  # The following code abides by the assumption that network traffic data is input with 
  # predetermined number of columns. In this case 41. With this in mind and considering 
  # how the way data is streamed into the function or traffic collection change, the code 
  # provided is open to updates via re-editing or adding sections to accomdate the input of 
  # new types of data sets.
  ###########################################################################################
  
  ## Read in the Train+ and Test+ Data sets
  #train <- "C:/+Data/Intrusion/KDDTrain+_20Percent.txt"
  #test <- "C:/+Data/Intrusion/KDDTest+.txt"
  
  #train <- "C:/Users/Don/Desktop/KDDTrain+_20Percent.txt"
  #test <- "C:/Users/Don/Desktop/KDDTest+.txt"
  
  ###########
  # Libraries
  ###########
  library(dplyr)
  library(e1071) # SVM
  library(caret)
  library(data.table) 
  library(rgl) # 3D scatterplot
  library(caret) # Training SVM
  
  ######
  # Data
  ######
  
  # The training set is representative of a data set that contains the categories of normal
  # and attack, both known and unkown. This is the set that can be manually updated upon the 
  # discovery a new type of attack. The training set can be thought of as a type of dicitonary
  # that contains the information on known attacks. 
  
  # The test set is representative of our network traffic data being streamed into the set
  # in real time. It is meant to serve as means to be able to potentailly label the data 
  # for use in classifying categories on data set in real time. 
  
  # Training set of data is the data that contains the labeled data of categories
  train <- trainset
  # Test set is a data set of network connections that is to have labels added to it
  # via the preprocessing and clustering methods
  test <- testset
  
  test <- test[, 1:41, with = FALSE]
  
  #########################################################################################
  # Preprocessing: Category labeling, Correlation Based Feature Selection and Normalization
  #########################################################################################
  
  #########################
  ## Attack Category Labels
  #########################
  
  # The provided data sets have each specific type of attack labeled in column 41. While
  # we want an ids that is able to accurately label and recognize each individual attack
  # on its own, we first want to make sure that it's able to classify each connection by 
  # a specified attack category. In this case, the categories in question are DOS, u2r,
  # r2l, probing, and normal. The data sets have a large range of connections that fall 
  # under the category of normal and DOS, which is why here we seek to train the SVM 
  # to recognize all five groups first, regardless of how much normal and DOS connections
  # are present.
  
  categorize <- function(data){
    #--------#
    # normal
    #--------#
    ids_normal <- filter(data, V42 == "normal")
    normal <- rep("normal", nrow(ids_normal))
    ids_normal <- cbind(ids_normal, normal)
    
    #-----#
    # DOS 
    #-----#
    ids_DOS <- filter(data, V42 == "back" | V42 == "land" | V42 == "neptune" | V42 == "pod" 
                      | V42 == "smurf" | V42 == "teardrop" | V42 == "apache2" | V42 == "udpstorm"
                      | V42 == "processtable" | V42 == "worm")
    DOS <- rep("DOS", nrow(ids_DOS))
    ids_DOS <- cbind(ids_DOS,DOS)
    
    #------#
    # Probe
    #------#
    ids_probe <- filter(data, V42 == "satan" | V42 == "ipsweep" | V42 == "nmap" 
                        | V42 == "portsweep" | V42 == "mscan" | V42 == "saint")
    probe <- rep("probe", nrow(ids_probe))
    ids_probe <- cbind(ids_probe, probe)
    #-----#
    # r2l
    #-----#
    ids_r2l <- filter(data, V42 == "guess_passwd" | V42 == "ftp_write" | V42 == "imap" 
                      | V42 == "phf" | V42 == "multihop" | V42 == "warezmaster"
                      | V42 == "warezclient" | V42 == "spy" | V42 == "xlock" | V42 == "xsnoop"
                      | V42 == "snmpguess" | V42 == "snmpgetattack" | V42 == "httptunnel"
                      | V42 == "sendmail" | V42 == "named")
    r2l <- rep("r2l", nrow(ids_r2l))
    ids_r2l <- cbind(ids_r2l, r2l)
    #-----#
    # u2r
    #-----#
    ids_u2r <- filter(data, V42 == "buffer_overflow" | V42 == "loadmodule" | V42 == "rootkit"
                      | V42 == "perl" | V42 == "sqlattack" | V42 == "xterm" | V42 == "ps")
    u2r <- rep("u2r", nrow(ids_u2r))
    ids_u2r <- cbind(ids_u2r, u2r)
    #---------#
    # unknown
    #---------#
    ids_unknown <- filter(data, V42 != "normal" & V42 != "back" & V42 != "land" 
                          & V42 != "neptune" & V42 != "pod" & V42 != "smurf" & V42 != "teardrop"
                          & V42 != "satan" & V42 != "ipsweep" & V42 != "nmap" & V42 != "portsweep"
                          & V42 != "guess_passwd" & V42 != "ftp_write" & V42 != "imap" 
                          & V42 != "phf" & V42 != "multihop" & V42 != "warezmaster" 
                          & V42 != "warezclient" & V42 != "spy" & V42 != "buffer_overflow" 
                          & V42 != "loadmodule" & V42 != "rootkit")
    unknown <- rep("unknown", nrow(ids_unknown))
    ids_unknown <- cbind(ids_unknown, unknown)
    
    #--------------------------------------------#
    # Label the columns in each new data frame
    #--------------------------------------------#
    colnames(ids_DOS)[ncol(ids_DOS)] <- "V44"
    colnames(ids_probe)[ncol(ids_probe)] <- "V44"
    colnames(ids_u2r)[ncol(ids_u2r)] <- "V44"
    colnames(ids_r2l)[ncol(ids_r2l)] <- "V44"
    colnames(ids_normal)[ncol(ids_normal)] <- "V44"
    colnames(ids_unknown)[ncol(ids_unknown)] <- "V44"
    
    data <- rbind(ids_DOS, ids_probe, ids_r2l, ids_u2r, ids_normal, ids_unknown)
    
    result <- list(Categorized_Data = data)
    return(result)
  }
  
  # Training Set: Contains labels with information
  train <- categorize(train)$Categorized_Data
  
  ######################################################
  # Remove the Category columns and store for later use. 
  ######################################################
  # Remove the Category labels from Training set, 
  # such that we can combine with the unlabeled 
  # training set.
  
  train_categories <- as.data.table(as.factor(train$V44))
  
  #  train <- train[, 1:41, with = FALSE]
  train <- train[, 1:41]
  
  ##############################
  # Combine data set for testing
  ##############################
  # Combine the training and test data set, such that 
  # we are able to applly our methods on a full 
  # data set and be able to predcit on the test set.
  full <- rbind(train, test)
  
  ########################################
  ## Convert symbolic variables to numeric
  ########################################
  
  # In this phase we want to take in our train and test data and convert any non-numeric values
  # to numeric. This is done in order to ensure the use of the data set with our PCA function.
  
  num.convert <- function(data){
    for(i in 1:ncol(data)){
      if(class(data[[i]]) == "character"){
        # Convert to Factor
        data <- data[,(i):=lapply(.SD,as.factor), .SDcols=i]
        # Convert to numeric
        data <- data[,(i):=lapply(.SD,as.numeric), .SDcols=i]
      }
    }
    result <- list(num_conversion = data)
    return(result)
  }
  
  num.full <- num.convert(full)$num_conversion
  
  ############################################
  ## Remove non-numeric variables from data set
  ############################################
  # This is done in order for use in the PCA
  
  # Function that returns the column names of numeric type columns
  numset <- function(data){
    # Determine which columns of the num.train data table are of 
    # class numeric
    colclass <- which(sapply(data, class) == "numeric")
    
    # Set the column names to a variable
    numcol <- names(colclass)
    
    # Subset the data table by columns of type numeric
    data <- data[,numcol,with = FALSE]
    
    result <- list(numeric_dataset = data)
    return(result)
  }
  
  
  num.full <- numset(num.full)$numeric_dataset
  
  ################
  ## Normalization
  ################
  # Now that we have the reduced data frame from our PCA, we will normalize the scores in order
  # allow the comparison of the corresponding normalized values for our training data set 
  # in order to eliminate the effects of any gross influences. In other words, we are 
  # normalizing the training and test data sets in order to improve our accuracy and detection
  # in the data set. We will be using min-max normalization to normalize the data to range of
  # 0 - 1. 
  # Guide:
  # norm.comp.train = normalized components training data set
  
  normalize_func <- function(num.data, origin.data){
    #########################################
    ### Minimum Maximum Normaliztion Function
    #########################################
    
    minmaxNorm <- function(x){
      (x - min(x, na.rm = TRUE))/(max(x,na.rm = TRUE) - min(x,na.rm = TRUE))
    }
    
    # Apply minmaxNorm function to entire data frame
    norm.num.data <- as.data.table(lapply(num.data,minmaxNorm))
    
    result <- list(norm_num_data = norm.num.data)
    return(result)
  }
  # Normalize the Full data set
  norm.num.full <- normalize_func(num.full,full)$norm_num_data
  
  ##########################################################################
  ## Feature Selection: Correlation-Based Principal Component Analysis (PCA) 
  ##########################################################################
  
  # The PCA function to be used here, princomp(), does not allow for columns with constant
  # variables. In this case, there are two columns in the test set that have columns of only
  # 0. While in real world analysis, this case may not arise as often, here we will be adding
  # component that removes this two columns for the sake of our ids. The columns in question
  # are columns 20 and 21 of the NSL_KDD test data set.
  # num.train = numeric training set
  
  ########
  ### PCA
  ########
  pca_func <- function(data, correlation = TRUE){
    pca <- princomp(data, cor = correlation)
    
    result <- list(pca_results = pca)
    return(result)
  }
  
  pca_full <- pca_func(norm.num.full)$pca_results
  
  ###############################################################
  #### Select components that explain between 80-90% of the data
  ###############################################################
  component_select <- function(pca_data, norm.num.data){
    vars.data <- pca_data$sdev^2 
    var.prop <- vars.data/sum(vars.data)
    cumu.prop <- cumsum(var.prop)
    
    # Create a for loop to check for a satisfactory cumulative proportion
    for(i in 1:ncol(norm.num.data)){
      # Check if the cumulative proportion of the summary PCs is over 80%
      # but less than 90%
      if(cumu.prop[i] > 0.80 && cumu.prop[i] < 0.90){
        # Store the data in new variable
        comp.data <- pca_data$scores[,1:i]
      }
    }
    
    # Convert matrix to data table
    comp.data <- as.data.table(comp.data)
    
    result <- list(comp_data = comp.data)
    return(result)
  }
  
  comp.full <- component_select(pca_full, norm.num.full)$comp_data
  
  # Separate full component data set into the original 
  # test and train observations, such that we can 
  # add labels to the train set.
  
  comp.train <- comp.full[1:nrow(train),]
  comp.test <- comp.full[(nrow(train)+1):nrow(comp.full),]
  
  # Add labels to comp.train
  comp.train <- comp.train[, Category := train_categories]
  
  # Combine the comp.train and comp.test data set
  # such that we can sample for testing
  
  comp.full <- rbind(comp.train[,1:(ncol(comp.train)-1),with = FALSE], comp.test)
  
  ##################
  ## Sample the data
  ##################
  # Here we will sample the data such that 2000 rows are from train and 1000
  # are from test
  
  full_train <- comp.train
  full_test <- comp.test
  
  comp.full.samp <- rbind(full_train[,1:(ncol(full_train)-1), with = FALSE], full_test)
  
  ########################################
  # Cluster Anlaysis: k-medoids clustering
  ########################################
  # Once the normalized PCA score data of training and test set is obtained, we cluster 
  # and label the training and test data using the k-medoids clustering techinque. The labeled 
  # training data is to then be used for training the SVM classifcation technique, such 
  # that the labels added to the test set have a desired accuracy and detection rate when 
  # classified by the SVM. 
  # Guide: 
  # train.cat = Number of unique categories in training data set
  
  
  #####################
  ## Cluster Validation
  #####################
  
  # We seek to use cluster validation in order to determine the correct number of clusters
  # that should result in both the train and test data sets. Once we have the desired k as 
  # seen from the results of the test set, we then use this k in our evaluation of the 
  # test set. Here we will be using the clValid package in R.
  
  # The following are parameters necessary for the training phase of 
  # the cluster validation process. train.cat provides us with 
  # the number of unique categories in the training set, while 
  # int.med yields a random sample of unique medoids to be used in 
  # our PAM function.
  
  ##############################################################################
  ## Store Number of unique categories in normalized component training data set
  ##############################################################################
  train.cat <- length(unique(full_train[,Category]))
  
  
  ##########################################################
  ## Perform k-medoids clustering with predefined parameters 
  ##########################################################
  # The following clustering technique will be applied to both the norm.comp.train and
  # test data sets
  # The k-medoids clustering function will take in the train.cat and int.med
  # parameters that have been created in order to cluster the component training
  # data such that the labels that are to be placed on the testing data in preparation for
  # the SVM classifcation process. 
  # Caution:This process as well as with the SVM method can be the most time consuming 
  # when it comes to much large data sets. 
  
  # In both functions, we standardize the data in order to improve the 
  # the overal detection rate. As discussed in "A New Clustering Approach
  # For Anomaly Detection" pdf reference.
  
  
  clara.func <- function(data){
    
    k <- cluster::clara(data[, 1:(ncol(data)-1), with = FALSE], k = train.cat, stand = FALSE,
                        medoids.x = TRUE, keep.data = TRUE, metric = "manhattan")
    
    results <- list(medoids = k$medoids, id.med = k$id.med, clustering = k$clustering,
                    objective = k$objective, isolation = k$isolation, clusinfo = k$clusinfo,
                    silinfo = k$silinfo, diss = k$diss, call = k$call, data = k$data)
    return(results)
  }
  
  #######################
  ## Newly clustered data
  #######################
  
  clust.full.data.samp = clara.func(comp.full)
  
  ##################
  ## 3D Scatter Plot
  ##################
  
  # Here we add in a function which reads in three components from our data 
  # set as they pertain to the newly clustered data. 
  # The output will be a 3D scatterplot with the clustered data as described by the 
  # variablity explained by the components.
  # Here we want a function that outputs 3 components and the amount of
  # variablity described by the three. 
  # Create a function that takes in the last 3 component columns of each
  # data set. 
  
  # Join the last two components in the set with their column number
  # as well with the string of the percent of variance explained.
  # Create an interactive function that takes in the amount of varaince
  # you want to explain and outputs the two components that do. 
  # "Component" + as.character(ncol(comp.full.samp)) + summary(pca_full)[i,j] (for the percent)
  # "Component" + as.character((ncol(comp.full.samp)-1)) + summary(pca_full)[i,j] (for the percent)
  
  # comp.name <- paste("Component", ncol(comp.full.samp)-1, sep = " ")
  # comp.name2 <- paste("Component", ncol(comp.full.samp), sep = " ")
  
  # plot3000 <- plot3d(x = comp.full.samp[,(ncol(comp.full.samp)-1), with = FALSE][[1]],
  #                   y = comp.full.samp[,ncol(comp.full.samp), with = FALSE][[1]],
  #                   xlab = "Sample Size",
  #                   ylab = comp.name,
  #                   zlab = comp.name2,
  #                   col = clust.full.data.samp$clustering)
  
  library(pca3d)
  
  comp.name <- paste("Component", 1,  sep = " ")
  
  # Cumulative proportion
  PoV <- pca_full$sdev^2/sum(pca_full$sdev^2)
  PoVperc <- round(PoV*100,2)
  
  # Component percent of variance explained
  perc.1 <- round(PoV[[1]]*100,2)
  comp.perc <- paste("(",perc.1,"% explained variance)", sep="")
  comp.name <- paste(comp.name, comp.perc, sep = "")
  
  comp.name2 <- paste("Component", 2,  sep = " ")
  # Component percent of variance explained
  perc.2 <- round(PoV[[2]]*100,2)
  comp.perc2 <- paste("(",perc.2,"% explained variance)", sep="")
  comp.name2 <- paste(comp.name2, comp.perc2, sep = "")
  
  comp.name3 <- paste("Component", 3,  sep = " ")
  # Component percent of variance explained
  perc.3 <- round(PoV[[3]]*100,2)
  comp.perc3 <- paste("(",perc.3,"% explained variance)", sep="")
  comp.name3 <- paste(comp.name3, comp.perc3, sep = "")
  
  ##############################################
  # 2D Scatterplot PCA with k-medoids Clustering
  ##############################################
  
  #pca2d(as.matrix(comp.full.samp), components = 1:2,
  #      group = clust.full.data.samp$clustering,
  #      col = clust.full.data.samp$clustering,
  #      show.group.labels =  TRUE,
  #      axe.titles = c(comp.name, comp.name2))
  #pca_title <- paste("PCA with k-medoid Clustering: \n Sample Size of",
  #                   nrow(comp.full.samp), sep = " ")
  
  #title(pca_title)
  
  #legend('bottomright', cex=.8, ncol = 2, inset = .002,
  #       text.font = 2, title = "Cluster: ",
  #       legend = levels(factor(clust.full.data.samp$clustering)),
  #       col = levels(factor(clust.full.data.samp$clustering)),
  #       pch = c(16,17,15,18,16),
  #       merge = F, bty = 'n')
  
  ##############################################
  # 3D Scatterplot PCA with k-medoids Clustering
  ##############################################
  
  ## Removed due to computation time delay when output a small small sample
  ## Possible inclusion to come with later update. For now the scatter plot
  ## yields by a standard 3D plot from sim.pids3.1()is sufficient for 
  ## displaying the PCA and k-medoid clustered information. 
  
  ## Computing the three dimensional large image of the full
  ## set takes time, removed for now
  
  ## An idx has been added to control the number of observations to be 
  ## taken for the 3D movie to run at an efficient speed.
  
  ## To up the sample size, but possibly slow down the script, change
  ## the number of observations to be taken for the idx variable then 
  ## rerun predictive.ids3.0 script as predictive.ids3.0() to test
  
  ## To slow down the rotations, change the rpm parameter of variable 
  ## rot below. Direction of rotation can be changed by manipulating the 
  ## axis parameter of rot.
  
  ## idx <- sample(nrow(comp.full.samp),500)
  ## pca3d(as.matrix(comp.full.samp[idx,]), components = 1:3,
  ##      group = clust.full.data.samp$clustering[idx],
  ##      col = clust.full.data.samp$clustering[idx],
  ##      show.axes = TRUE,radius = 0.75, show.ellipses = TRUE, bg =  "white",
  ##      axe.titles = c(comp.name, comp.name2, comp.name3)
  ## )
  
  ## axes3d()
  
  ## pca_title <- paste("PCA with k-medoid Clustering: Sample Size of",
  ##                   nrow(comp.full.samp[idx,]), sep = " ")
  
  ## title3d(pca_title)
  
  ## legend3d('right', cex=1, ncol = 1, inset = .02,
  ##        text.font = 1, title = "Cluster: ",
  ##        legend = levels(factor(clust.full.data.samp$clustering[idx])),
  ##        col = levels(factor(clust.full.data.samp$clustering[idx])),
  ##        pch = c(16,17,15,18,16),
  ##        merge = F, bty = 'o')
  
  
  ## rot <- spin3d( axis= c( 0 , 1, 0 ), rpm = 5)
  
  ## movie3d( rot, duration= 5)
  
  #########################################################
  # Classifaction: Support Vector Machine with Radial Basis
  #########################################################
  
  # Break into training and test set
  trainsamp <- comp.full.samp[1:nrow(full_train),]
  testsamp <- comp.full.samp[(nrow(full_train)+1):nrow(comp.full.samp),]
  
  # Add labels to trainsamp set for training of the SVM
  trainsamp <- trainsamp[,Category := full_train$Category]
  
  #svm_tune <- tune(svm, train.x= trainsamp[,1:(ncol(trainsamp)-1), with = FALSE],
  #                 train.y=trainsamp$Category, kernel=kernel, 
  #                 ranges=list(cost=10^(-1:3), gamma=c(.5,1,2)))
  
  #cost <- svm_tune$best.parameters[[1]]
  #gamma <- svm_tune$best.parameters[[2]]
  #svmtrainfit <- svm(as.factor(Category)~., data = trainsamp, 
  #                   kernel = kernel, cost = cost, 
  #                   gamma = gamma , cross = 10, scale = TRUE)  
  
  svmtrainfit <- svm(as.factor(Category)~., data = trainsamp, 
                     kernel = kernel, cost = cost,gamma = gamma)
  
  
  trainprediction <- predict(svmtrainfit,trainsamp[ ,1:(ncol(trainsamp)-1), with = FALSE])
  
  conf.mat.train <- confusionMatrix(trainprediction,trainsamp$Category,
                                    positive = "intrusion")
  
  #conf.mat.train
  
  testprediction <- predict(svmtrainfit, testsamp[,1:ncol(testsamp), with = FALSE])
  
  #testprediction
  
  ###########################
  # Plot SVM prediction model
  ###########################
  
  ## Add Prediction labels to testsamp
  testsamp <- testsamp[,Category := testprediction]
  
  
  #plot(svmtrainfit, trainsamp, Comp.2 ~ Comp.1)
  
  ## SVM Classification plot of the Test+ based on PIDS algorithm
  plot(svmtrainfit, testsamp, Comp.2 ~ Comp.1)
  
  ########
  # Output
  ########
  
  ## Combine original labeled data set with predicted values
  
  test <- test[,Prediction := testprediction]
  
  ## Create binary data sets of attacks vs. normal
  
  ## Output ROC performance curve of each of the above
  
  # Subset to only include connections that are being viewed as attacks
  
  test <- filter(test, Prediction != "normal")
  
  # Compensate for the 87% Accuracy by resampling the data that is not TP
  
  # Histogram: To visualize our results
  
  # Heatmap: To visualize the attacks based on alternative variables
  
  result <- list(AttConnections = test)
  
  return(result)
}


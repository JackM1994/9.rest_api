'use strict';
const Sequelize = require('sequelize');

module.exports = (sequelize) => {
    class Courses extends Sequelize.Model{}
    Courses.init({
        id: {
            type: Sequelize.INTEGER,
            autoIncrement: true,
            primaryKey: true,
            allowNull: false
        },
       
        title: {
            type: Sequelize.STRING,
            allowNull: false,
            validate:{
                notNull:{
                    msg: 'Please provide a value for "title"'
                },
                notEmpty: {
                    msg: 'Please provide a value for "title"'
                }
            }
        },
        description: {
            type: Sequelize.TEXT,
            allowNull: false,
            validate: {
                notNull: {
                    msg: 'Please provide a value for "description"'
                },
                notEmpty: {
                    msg: 'Please provide a value for "description"'
                }
            }
        },
        estimatedTime: {
            type: Sequelize.STRING,
            allowNull: true
        },
        materialsNeeded: {
            type:Sequelize.STRING,
            allowNull: true
        }
    }, { sequelize });
    
    //association bewteen courses model and users model
    Courses.associate = (models) => {
        Courses.belongsTo(models.Users, {
           foreignKey: {
               fieldName: 'userId',
               allowNull: false,
               validate: {
                   notNull: {
                       msg: 'User Id is required'
                   }
               } 
            },
           
        });
    }

    return Courses;
};
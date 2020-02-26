'use strict';
const Sequelize = require('sequelize');

module.exports = (sequelize) => {
    class Users extends Sequelize.Model{}
    Users.init({
        id: {
            type: Sequelize.INTEGER,
            allowNull: false,
            autoIncrement: true,
            primaryKey: true,
        },
        firstName: {
            type:Sequelize.STRING,
            allowNull: false,
            validate: {
                notEmpty: {
                    msg: '"First Name" is required'
                }
            }

        },
        lastName: {
            type: Sequelize.STRING,
            allowNull: false,
            validate: {
                notEmpty: {
                    msg:'"Last Name is required"'
                }
            }
        },
        emailAddress: {
            type: Sequelize.STRING,
            allowNull: false,
            unique: true,
            validate: {
                isEmail: {
                    msg: 'Email Address must be valid '
                }
            }
        },
        password: {
            type:Sequelize.STRING,
            allowNull: false,
            validate: {
                len:{
                    args: 3
                }
            }
        }
    }, { sequelize });
    
    //associations between User Model and Course model
    Users.associate = (models) => {
        Users.hasMany(models.Courses, {
            foreignKey: {
                fieldName:'userId',
                allowNull: false
            }
        });
    };

    return Users;
};